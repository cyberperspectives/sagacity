<?php

/**
 * File: parse_iavm_cve.php
 * Author: Ryan Prather
 * Purpose: Script to parse iavm_to_cve(u).xml file received from DISA
 * Created: Jul 9, 2014
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
 *  - Jul 9, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated and converted to constants
 */
$cmd = getopt("f:", array('debug::', 'help::'));

if (!isset($cmd['f']) || isset($cmd['help'])) {
  usage();
  exit;
}

include_once 'config.inc';
include_once "database.inc";
include_once 'helper.inc';

chdir(DOC_ROOT . "/tmp");

set_time_limit(0);

$sys = new db();

$db = new mysqli(DB_SERVER, 'web', db::decrypt_pwd(), 'sagacity');
if ($db->connect_errno) {
  die($db->connect_error);
}

$doc = new DOMDocument();
$doc->load($cmd['f']);

$items = getValue($doc, 'IAVM', null, true);

foreach ($items as $node) {
  $pdi_id = 0;

  $vms = getValue($doc, 'S/@VMSKey', $node);
  $vms = preg_replace("/V0{1,6}/", "V-", $vms);
  $iavm_id = getValue($doc, 'S/@IAVM', $node);
  $title = getValue($doc, 'S/@Title', $node);
  $cat = substr_count(getValue($doc, 'S/@Severity', $node), 'I', 7);
  $rel_date = getValue($doc, 'S/@ReleaseDate', $node);
  $rel_dt = new DateTime($rel_date);

  $cves = getValue($doc, 'CVEs/CVENumber', $node, true);

  $stig = $sys->get_Stig($iavm_id);
  $iavm = $sys->get_IAVM($iavm_id);

  print $iavm_id . PHP_EOL;

  if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
    $stig = $stig[0];
    $pdi_id = $stig->get_PDI_ID();
  }
  else {
    if ($iavm) {
      $stig = new stig($iavm->get_PDI_ID(), $iavm_id, $title);
      $sys->add_Stig($stig);
    }
    else {
      $pdi = new pdi(null, $cat, $rel_dt->format("Y-m-d"));
      $pdi->set_Short_Title($title);
      $pdi->set_Group_Title($title);
      $pdi_id = $sys->save_PDI($pdi);

      $stig = new stig($pdi_id, $iavm_id, $title);
      $sys->add_Stig($stig);
    }
  }

  if ($iavm) {
    if ($cves->length) {
      foreach ($cves as $cve_node) {
        if (substr($cve_node->textContent, 0, 3) == 'CAN') {
          $cve = 'CVE' . substr($cve_node->textContent, 3);
        }
        else {
          $cve = $cve_node->textContent;
        }

        if (!in_array($cve, $iavm->get_CVE())) {
          $iavm->add_CVE($cve);
        }
      }

      $sys->save_IAVM($iavm);
    }
  }
}

function usage() {
  print <<<EOO
Purpose: To import the cve-to-iavm(u).xml file retrieved from http://iasecontent.disa.mil/stigs/xml/iavm-to-cve%28u%29.xml

Usage: php parse_iavm_cve.php -f={file} [--debug] [--help]

 -f={file}          The file to import

 --debug            Debugging output
 --help             This screen

EOO;
}
