<?php

/**
 * File: parse_host_data_collection.php
 * Author: Ryan Prather
 * Purpose: This script will parse the configuration files that are passed to it and update the finding details
 * Created: May 29, 2014
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
 *  - May 29, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter, and functions after class merger
 *  - Jan 30, 2017 - Updated to use parse_config.ini file
 *  - Feb 15, 2017 - Moved MYSQL_DT_FROMAT constant to inc/helper.inc with other constants
 */
$conf = parse_ini_file("parse_config.ini", false);

$cmd = getopt(array('debug::', 'help::'));

if (isset($cmd['help'])) {
  usage();
  exit;
}

chdir($conf['doc_root']);

include_once 'config.inc';
include_once "database.inc";
include_once 'helper.inc';

set_time_limit(0);

$db = new db();

if ($tgt_id = $db->check_Target($conf['ste'], $conf['target'])) {
  $tgt = $db->get_Target_Details($conf['ste'], $tgt_id)[0];
}
else {
  Sagacity_Error::err_handler("Could not find host ID " . $conf['target']);
  die;
}

$err = new Sagacity_Error($tgt->get_Name() . "_data_col.log");

chdir(TMP . "/data_collection/" . $tgt->get_Name());

$os = $db->get_Software($tgt->get_OS_ID())[0];
$sw_arr = $db->get_Target_Software($tgt->get_ID());
$sw_str = '';

foreach ($sw_arr as $key => $sw) {
  $sw_str .= $sw->get_Man() . " " . $sw->get_Name() . " " . $sw->get_Version() . PHP_EOL;
}

$answer_files = glob("*-answers.txt");

if (isset($conf['overwrite'])) {
  foreach ($answer_files as $file) {
    unlink($file);
  }
  $answer_files = array();
}

if (!count($answer_files)) {
  if ($tgt->get_Cat_ID()) {
    $qa = $db->get_Interview_Answers($tgt->get_Cat_ID());
    $cat = $db->get_Category($tgt->get_Cat_ID())[0];
    $qa_handle = fopen($cat->get_Name() . "-answers.txt", "w");
    foreach ($qa as $key => $ans) {
      fwrite($qa_handle, $ans->key . "=" . ($ans->answer ? "y" : "n") . PHP_EOL);
    }
    fclose($qa_handle);
  }
}

$findings = $db->get_Finding($tgt, null, null, false, "Not Reviewed");
$run_stigs = array();
$files = glob("*.*");
$hostfiles = array();
$filepermsSize = 0;
$minfilepermsSize = 15000000;

foreach ($files as $file) {
  if (preg_match("/summary|error|checksum/i", $file)) {
    continue;
  }
  if (preg_match("/\-answers\.txt/i", $file)) {
    $fname = "answerfile";
  }
  elseif (preg_match("/\-config\.txt/", $file)) {
    $fname = "cisco_config";
  }
  elseif ($file == "file_permissions.txt") {
    $filepermsSize = filesize($file);
    $fname = "file_permissions";
  }
  else {
    $fname = preg_replace("/[\.][^\.]+$/", '', basename($file));
  }
  $hostfiles["$fname"] = preg_replace("/[^[:print:]]/", "", file($file));
}

// print "finding count: ".count($findings).PHP_EOL;

$scan_id = 0;

/** @var finding $find */
foreach ($findings as $find) {
  $ret = array();
  if ($find->get_Scan_ID()) {
    $scan_id = $find->get_Scan_ID();
  }
  elseif ($scan_id) {
    $find->set_Scan_ID($scan_id);
  }
  else {
    $existing_scan = $db->get_ScanData($tgt->get_STE_ID(), $tgt->get_Name() . " data collection");
    if (count($existing_scan)) {
      $scan = $existing_scan[0];
      $scan_id = $scan->get_ID();
    }
    else {
      $src = $db->get_Sources("Data Collection");
      $dt = new DateTime();
      $ste = $db->get_STE($tgt->get_STE_ID())[0];
      $scan_id = $db->save_Scan(new scan(null, $src, $ste, 1, $tgt->get_Name() . " data collection", $dt->format('Y-m-d H:i:s')));
    }
    $find->set_Scan_ID($scan_id);
  }
  $stig = $db->get_STIG_By_PDI($find->get_PDI_ID());
  if (!is_a($stig, 'stig')) {
    continue;
  }

  $function = $db->get_STIG_Function($stig, $tgt);

  if (empty($function)) {
    continue;
  }

  $stig_function = preg_replace("/[\.\-\ ]+/", "", $stig->get_ID());
  if (is_numeric(substr($stig_function, 0, 1))) {
    $stig_function = "S" . $stig_function;
  }
  if (!in_array($stig_function, $run_stigs)) {
    eval($function);
    $run_stigs[] = $stig_function;
  }

  $start = new DateTime();
  $ret = call_user_func($stig_function);
  $end = new DateTime();
  $diff = $end->diff($start);

  $err->script_log("Tweak function: $stig_function" . PHP_EOL . "Result: " . print_r($ret, true));
  if ($diff->format("%s") > 3) {
    $err->script_log("Tweak function execution exceeded 3 seconds.");
  }

  $find->set_Finding_Status_By_String($ret['status']);
  $find->prepend_Notes("(Script) " . $ret['notes']);

  $db->update_Finding($find);
}

function usage() {
  print <<<EOO
Purpose: To execute tweak function to limit the number of manual checks that need to be accomplished.

Usage: php parse_host_data_collection.php -s={ST&E ID} -t={target name} [--debug] [--overwrite] [--help]

 -s={ST&E ID}       The ST&E ID the results are going to imported for
 -t={target name}   The name of the target this data is for (can be formal name, hostname, or IP address)

 --overwrite        Will create a new answer file for this target using what is in the database
 --debug            Debugging output

EOO;
}
