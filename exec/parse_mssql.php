<?php

/**
 * File: parse_mssql.php
 * Author: Ryan Prather
 * Purpose: Parse MSSQL SRR result files
 * Created: Jan 15, 2015
 *
 * Portions Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 15, 2015 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter,
 * 					added file purpose, and updated functions after class merger
 *  - Oct 24, 2016 - Updated class extension after rename from XMLParser to scan_xml_parser
 *  - Mar 4, 2017 - Removed Thread class calls
 */
$cmd = getopt("f:s:d:", array('debug::', 'help::'));

if (!isset($cmd['f']) || !isset($cmd['s']) || isset($cmd['help'])) {
  usage();
  exit;
}

chdir($cmd['d']);

include_once 'config.inc';
include_once 'helper.inc';
include_once 'xml_parser.inc';

chdir(DOC_ROOT . "/tmp");
set_time_limit(0);

$base_name = basename($cmd['f']);

$db = new db();

class mssql_parser extends scan_xml_parser {

  var $tgt;
  var $tag;
  var $schema;
  var $vms;
  var $stig;
  var $status;
  var $notes;

  public function __construct($ste_id_in, $fname_in) {
    parent::__construct($this, $ste_id_in, $fname_in);
    $this->host_list = array();
    $this->count = 0;
    $this->db->update_Running_Scan($this->scan->get_File_Name(), array('name' => 'pid', 'value' => getmypid()));
  }

  public function IMPORT_FILE_ASSET($attrs) {
    $this->tag = array();
  }

  public function IMPORT_FILE_ASSET_ASSET_ID($attrs) {
    if (isset($attrs['TYPE'])) {
      $this->tag_id = str_replace(" ", "_", $attrs['TYPE']);
    }
    else {
      $this->tag_id = null;
    }
  }

  public function IMPORT_FILE_ASSET_ASSET_ID_data($data) {
    if ($this->tag_id == "IP_ADDRESS") {
      if (preg_match("/\./", $data)) {
        $this->tag_id = "IP4_ADDRESS";
      }
      elseif (preg_match("/\:/", $data)) {
        $this->tag_id = "IP6_ADDRESS";
      }
    }

    $this->tag[$this->tag_id] = $data;
  }

  public function IMPORT_FILE_ASSET_ELEMENT($attrs) {
    // finished ingesting the target data...need to check for target existence
    if ($tgt_id = $this->db->check_Target($this->ste_id, $this->tag['HOST_NAME'])) {
      $this->tgt = $this->db->get_Target_Details($this->ste_id, $tgt_id)[0];
    }
    elseif (isset($this->tag['IP4_ADDRESS']) && $tgt_id = $this->db->check_Target($this->ste_id, $this->tag['IP4_ADDRESS'])) {
      $this->tgt = $this->db->get_Target_Details($this->ste_id, $tgt_id)[0];
    }
    else {
      $this->tgt = new target($this->tag['HOST_NAME']);
      $this->tgt->set_STE_ID($this->ste_id);

      $sw = new software("cpe:/o:generic:generic:-");
      $os = $this->db->get_Software($sw)[0];

      $this->tgt->set_OS_ID($os->get_ID());

      if (isset($this->tag['IP4_ADDRESS'])) {
        $int = new interfaces(null, null, null, $this->tag['IP4_ADDRESS'], null, $this->tag['HOST_NAME'], $this->tag['HOST_NAME'], null);
        $this->tgt->interfaces[] = $int;
      }

      if (isset($this->tag['IP6_ADDRESS'])) {
        $int = new interfaces(null, null, null, null, $this->tag['IP6_ADDRESS'], $this->tag['HOST_NAME'], $this->tag['HOST_NAME'], null);
        $this->tgt->interfaces[] = $int;
      }

      $this->db->save_Target($this->tgt);
    }
  }

  public function IMPORT_FILE_ASSET_TARGET($attrs) {
    $this->updated_findings = array();
    $this->new_findings = array();
    $this->schema = null;
  }

  public function IMPORT_FILE_ASSET_TARGET_IDENTIFIER_data($data) {
    $this->schema = $data;
  }

  public function IMPORT_FILE_ASSET_TARGET_FINDING($attrs) {
    $this->vms = null;
    $this->stig = null;
    $this->notes = null;
    $this->status = "Not Reviewed";
  }

  public function IMPORT_FILE_ASSET_TARGET_FINDING_FINDING_ID_data($data) {
    $vms_id = preg_replace("/V0+/", "V-", $data);
    $vms = $this->db->get_GoldDisk($vms_id);

    if (is_array($vms) && count($vms) && isset($vms[0]) && is_a($vms[0], 'golddisk')) {
      $this->vms = $vms[0];
    }
    else {
      $this->log->script_log("VMS $vms_id not found", E_WARNING);
      $this->skip = true;
      return;
    }

    if (!empty($this->vms)) {
      $this->stig = $this->db->get_STIG_By_PDI($this->vms->get_PDI_ID());
    }
  }

  public function IMPORT_FILE_ASSET_TARGET_FINDING_FINDING_STATUS_data($data) {
    if ($data == "O") {
      $this->status = "Open";
    }
    elseif ($data == "NF") {
      $this->status = "Not a Finding";
    }
    else {
      $this->status = "Not Reviewed";
    }
  }

  public function IMPORT_FILE_ASSET_TARGET_FINDING_FINDING_DETAILS_data($data) {
    if (!empty($this->schema)) {
      $this->notes = $this->schema . " - " . $data;
    }
    else {
      $this->notes = $data;
    }
  }

  public function IMPORT_FILE_ASSET_TARGET_FINDING_end() {
    if ($this->skip) {
      $this->skip = false;
      return;
    }

    // check for finding
    $finding = $this->db->get_Finding($this->tgt, $this->stig);
    if (is_array($finding) && count($finding)) {
      $finding = $finding[0];
      if (false) {
        $finding = new finding();
      }

      $finding->prepend_Notes("(MSSQL) " . $this->notes);
      if ($finding->get_Finding_Status_String() != "Not Reviewed" && $finding->get_Finding_Status_String() != $this->status) {
        $finding->set_Finding_Status_By_String(
            $finding->get_Deconflicted_Status($this->status)
        );
      }
      else {
        $finding->set_Finding_Status_By_String($this->status);
      }

      $this->updated_findings[$finding->get_PDI_ID()] = $finding;
    }
    else {
      $finding = new finding(null, $this->tgt->get_ID(), $this->stig->get_PDI_ID(), $this->scan->get - ID(), $this->status, $this->notes, finding::NC, "MSSQL", 1);

      $this->new_findings[$this->stig->get_PDI_ID()] = $finding;
    }
    // if present in $new_findings, append notes
    // if present in $updated_findings, ? check for notes?
  }

  public function IMPORT_FILE_ASSET_TARGET_end() {
    $this->db->add_Findings_By_Target($this->updated_findings, $this->new_findings);
  }

}

$xml = new mssql_parser($cmd['s'], $cmd['f']);
$xml->debug = (isset($cmd['debug']) ? true : false);
//Enter xml code here
$xml->parse();

if (!$xml->debug) {
  rename($cmd['f'], DOC_ROOT . "/tmp/mssql/" . $base_name);
}

$db->update_Running_Scan($base_name, array("name" => "perc_comp", "value" => 100, "complete" => 1));

function usage() {
  print <<<EOO
Purpose: To import the MSSQL SRR result file from DISA

Usage: php parse_mssql.php -s={ST&E ID} -f={result file} [--debug] [--help]

 -s={ST&E ID}       The ST&E ID this result file is being imported for
 -f={result file}   The result file to import

 --debug            Debugging output
 --help             This screen

EOO;
}
