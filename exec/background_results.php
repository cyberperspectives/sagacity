<?php

/**
 * File: background_results.php
 * Author: Ryan Prather
 * Purpose: Background script file that will call appropriate function for files found
 * Created: Feb 26, 2014
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Feb 26, 2014 - File created
 *  - May 05, 2014 - Converted parsing functions to classes for threading
 *  - Sep 1, 2016 - Copyright updated, added CWD parameter option,
 * 					Converted to constants, made script execution platform independent
 *  - Oct 24, 2016 - Added debug output and cleaned up script string generation
 *  - Nov 7, 2016 - If it ain't broke, don't fix it! Had to revert to a previous version because intended improvements broke it
 *  - Dec 7, 2016 - Fixed bug where Windows threading was not being started,
 *                  Changed PHP constant to PHP_BIN, and make sure that script continues running until last result file is done.
 *  - Jan 30, 2017 - Converted script to use parse_config.ini file instead of command line parameters and set script to remove config file when all files are completely parsed
 *  - Feb 15, 2017 - Converted file_types constants to defined constants and removed unnecessary parameters from parse_* scripts string creation
 *  - Feb 21, 2017 - Fixed path issues with scripts not running
 *  - Oct 23, 2017 - Conditionally delete parse_config.ini only if not in DEBUG log level
 *  - Oct 27, 2017 - Fix to remove desktop.ini files if found
 */
error_reporting(E_ALL);

$cmd = getopt("t::", ["help::"]);

$conf = parse_ini_file("parse_config.ini", false);

if (isset($cmd['help']) || !is_numeric($conf['ste']) || !isset($conf['doc_root'])) {
  die(usage());
}
elseif (!file_exists($conf['doc_root'])) {
  die("Folder {$conf['doc_root']} doesn't exist" . PHP_EOL);
}

chdir($conf['doc_root']);

set_time_limit(0);

include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';
include_once 'vendor/autoload.php';

$debug = (LOG_LEVEL == E_DEBUG ? true : false);

check_path(TMP . "/echecklist");
check_path(TMP . "/nessus");
check_path(TMP . "/nmap");
check_path(TMP . "/scc");
check_path(TMP . "/stig_viewer");
check_path(TMP . "/terminated");
check_path(TMP . "/unsupported");

chdir(TMP);

$dbh = new db();

$files = glob("*.*");
$stack = [];
$running = [];
$time = 0;
$threads = [];

foreach ($files as $file) {
  $res = FileDetection($file);
  if ($debug) {
    Sagacity_Error::err_handler(print_r($res, true), E_DEBUG);
  }
  switch ($res['type']) {
    case NESSUS:
      $stack[] = array(
        'exec'   => 'nessus',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'nessus'
      );
      break;
    case SCC_XCCDF:
      $stack[] = array(
        'exec'   => 'scc_xccdf',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'scc_xccdf'
      );
      break;
    case STIG_VIEWER_CKL:
      $stack[] = array(
        'exec'   => 'stig_viewer',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'stig_viewer'
      );
      break;
    case TECH_ECHECKLIST_EXCEL:
      $ignore = false;
      if (isset($conf['ignore'])) {
        $ignore = true;
      }
      $stack[] = array(
        'exec'          => 'excel_echecklist',
        'file'          => $file,
        'ste'           => $conf['ste'],
        'ignore_hidden' => $ignore,
        'source'        => 'echecklist'
      );
      break;
    case ECHECKLIST_CSV:
      $stack[] = array(
        'exec'   => 'csv_echecklist',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'echecklist'
      );
      break;
    case PROC_ECHECKLIST_EXCEL:
      $stack[] = array(
        'exec' => 'proc_echecklist',
        'file' => $file,
        'ste'  => $conf['ste']
      );
      break;
    case HOST_DATA_COLLECTION:
      $stack[] = array(
        'exec'   => 'data_collection',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'target' => $cmd['t'],
        'source' => 'data_collection'
      );
      break;
    case NMAP_GREPABLE:
    case NMAP_TEXT:
    case NMAP_XML:
      $stack[] = array(
        'exec'   => 'nmap',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'nmap'
      );
      break;
    case MBSA_TEXT:
    case MBSA_XML:
      $stack[] = array(
        'exec'   => 'mbsa',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'mbsa'
      );
      break;
    case MSSQL_XML:
      $stack[] = array(
        'exec'   => 'mssql',
        'file'   => $file,
        'ste'    => $conf['ste'],
        'source' => 'mssql'
      );
      break;
    case DIRECTORY:
      break;
    case strpos("UNSUPPORTED", $file) !== false:
      rename($file, realpath(TMP . "/unsupported/" . basename($file)));
      break;
    default:
      error_log("Do not have a parser for " . $file);
  }
}

if ($debug) {
  Sagacity_Error::err_handler(print_r($stack, true), E_DEBUG);
}

foreach ($stack as $key => $s) {
  $existing = $dbh->get_Running_Script_Status($s['ste'], $s['file']);
  if (isset($existing['status']) && $existing['status'] == 'RUNNING') {
    unset($stack[$key]);
    continue;
  }

  $ignore = '';
  if ($s['source'] == 'echecklist' && $s['ignore_hidden']) {
    $ignore = " -i=1";
  }

  $stack[$key]['script'] = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
      " -c " . realpath(PHP_CONF) . " " .
      " -f " . realpath(DOC_ROOT . "/exec/parse_{$s['exec']}.php") . " --" .
      " -f=\"{$s['file']}\"" .
      $ignore .
      ($debug ? " --debug" : "");

  $dbh->add_Running_Script(basename($s['file']), $s['ste'], $s['source'], $conf['location']);
}

$proc = array();
$count = 0;

chdir(realpath(DOC_ROOT . "/exec"));

foreach ($stack as $s) {
  $threads[] = new Cocur\BackgroundProcess\BackgroundProcess($s['script']);
  end($threads)->run();

  sleep(3);
  $count++;

  while ($count >= MAX_RESULTS) {
    sleep(1);
    $count = $dbh->get_Running_Script_Count($conf['ste']);
  }
}

do {
  sleep(1);
}
while ($dbh->get_Running_Script_Count($conf['ste']));

if (!$debug) {
  unlink(DOC_ROOT . "/exec/parse_config.ini");
}

/**
 * Function to import SCC Oval XML Result files
 *
 * @param string $file
 */
function import_SCC_OVAL($file) {
  if (preg_match('/.*Results\_iavm\_(2009|2010)|Results\_USGCB/i', $file)) {
    return;
  }

  $target_data = array();
  $db = new db();
  $match = array();
  preg_match('/\_SCC-(\d\.?)+\_(\d{4}\-\d{2}\-\d{2}\_\d{6})\_OVAL/', $file, $match);
  $time_stamp = $match[2];
  $dt = DateTime::createFromFormat('Y-m-d_His', $time_stamp);

  $source = $db->get_Sources('SCC');
  $dom = new DOMDocument();
  $dom->load($file);

  $csv = fopen("scc/" . substr(basename($file), 0, -3) . "csv", 'w');
  $ste = $db->get_STE($GLOBALS['opt']['s'])[0];
  $scan = new scan(null, $source, $ste, 1, basename($file), $dt->format('Y-m-d H:i:s'));
  $scan->set_ID($db->save_Scan($scan));

  $x = new DOMXPath($dom);

  $sysinfo = $x->query('/oval-res:oval_results/oval-res:results/oval-res:system/oval-sc:oval_system_characteristics/oval-sc:system_info')->item(0);

  $target_data['os_name'] = $x->query('oval-sc:os_name', $sysinfo)->item(0)->textContent;
  $target_data['os_ver'] = $x->query('oval-sc:os_version', $sysinfo)->item(0)->textContent;
  $target_data['host_name'] = $x->query('oval-sc:primary_host_name', $sysinfo)->item(0)->textContent;
  $interfaces = $x->query('oval-sc:interfaces/oval-sc:interface', $sysinfo);
  $int_count = 0;

  foreach ($interfaces as $node) {
    $target_data['interface_name' . $int_count] = $x->query('oval-sc:interface_name', $node)->item(0)->textContent;
    $target_data['ip' . $int_count] = $x->query('oval-sc:ip_address', $node)->item(0)->textContent;
    $target_data['mac' . $int_count] = $x->query('oval-sc:mac_address', $node)->item(0)->textContent;

    $int_count++;
  }

  $defs = $x->query('/oval-res:oval_results/oval-def:oval_definitions/oval-def:definitions/oval-def:definition');

  foreach ($defs as $node) {
    $id = $node->getAttribute('id');
    print "Checking oval id: $id" . PHP_EOL;
    //$meta = $x->query('oval-def:metadata', $node)->item(0);

    $title = $x->query('oval-def:metadata/oval-def:title', $node)->item(0)->textContent;
    $desc = $x->query('oval-def:metadata/oval-def:description', $node)->item(0)->textContent;
    $plat = $x->query('oval-def:metadata/oval-def:affected/oval-def:platform', $node)->item(0)->textContent;

    $ext = $x->query('oval-def:criteria/oval-def:extend_definition', $node);

    if ($ext->length > 0) {
      $ext_def = $ext->item(0)->getAttribute('definition_ref');
      $ext_def_op = $x->query('oval-def:criteria', $node)->item(0)->getAttribute('operator');
    }
    else {
      $ext_def = '';
      $ext_def_op = '';
    }

    $ref = $x->query('oval-def:metadata/oval-def:reference', $node);
    $oval = $db->get_Oval($id);

    if ($oval->get_PDI_ID()) {
      print "current oval: " . print_r($oval, true);
      $oval->clear_References();
    }
    else {
      $oval = new oval(null, $id, $title, $desc, $plat, $ext_def, $ext_def_op);
    }

    foreach ($ref as $ref_node) {
      $source = $ref_node->getAttribute('source') == 'http://cce.mitre.org' ? 'CCE' : $ref_node->getAttribute('source');
      $url = $ref_node->hasAttribute('ref_url') ? $ref_node->getAttribute('ref_url') : '';
      $ref_id = $ref_node->getAttribute('ref_id');

      $oval->add_Reference(new oval_ref($id, $source, $url, $ref_id));

      if (is_null($oval->get_PDI_ID()) && $source == 'CCE') {
        $cce = $db->get_CCE($ref_id);

        if (!is_null($cce)) {
          $oval->set_PDI_ID($cce->get_PDI_ID());
        }
      }
    }

    if ($db->save_Oval($oval)) {
      error_log("Saved oval id: " . $oval->get_Oval_ID());
    }
    else {
      error_log("Error saving oval id: " . $oval->get_Oval_ID());
    }
  }
}

function usage() {
  print <<<EOO
Purpose: This program was written to look at all files in the /tmp directory, determine what parser is needed, then call that parser with the appropriate flags.

Usage: background_results.php -s={ste_id} [-i=1] [-t=1] [--help]

 -s={STE ID}        The ID of the ST&E to know what to assign the results to
 -i=1               Ignore hidden Excel worksheets (only used on Excel eChecklist files) (defaulted to false)
 -t={Target Name}   The name of the target to evaluate (only used on host data collection)

 --help             This screen

EOO;
}
