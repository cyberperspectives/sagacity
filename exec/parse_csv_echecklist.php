<?php

/**
 * File: parse_csv_echecklist.php
 * Author: Ryan Prather
 * Purpose: Background script to parse CSV eChecklist files
 * Created: May 9, 2014
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
 *  - May 9, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter, and
 * 					Updated to use correct functions after class mergers
 *  - Jan 30, 2017 - Updated to use parse_config.ini file
 *  - Mar 4, 2017 - Removed Thread class calls
 */
$start = new DateTime();

$cmd = getopt("f:", array('debug::', 'help::'));

if (!isset($cmd['f']) || isset($cmd['help'])) {
  die(usage());
}

$conf = parse_ini_file("parse_config.ini");

if (!$conf) {
  die("Could not find parse_config.ini configuration file");
}

chdir($conf['doc_root']);

print "Start Time: " . $start->format("H:i:s") . PHP_EOL;

include_once 'config.inc';
include_once "database.inc";
include_once 'helper.inc';

chdir(TMP);

set_time_limit(0);

$dbh = new db();
$base_name = basename($cmd['f']);
$err = new Sagacity_Error($base_name);

if (!file_exists($cmd['f'])) {
  $dbh->update_Running_Scan($base_name, array('name' => 'status', 'value' => 'ERROR'));
  $err->script_log("File not found", E_ERROR);
}

$dbh->update_Running_Scan($base_name, array('name' => 'pid', 'value' => getmypid()));

$error = array();
$success = array();
$tgts = array();
$finding_count = array();
$sum = '';
$host_list = array();
$src = $dbh->get_Sources('eChecklist');
$handle = fopen($cmd['f'], "r");

// Get the headers (might be one extra line)
$eol = true;
$header_lines = 0;
while ($data = fgetcsv($handle)) {
  $header_lines++;
  if (preg_match('/STIG[\_ ]ID/i', $data[0])) {
    $eol = false;
    break;
  }
}

if ($eol) {
  $err->script_log("Got to end of " . $cmd['f'] . " without finding 'STIG ID'", E_ERROR);
}

// add a new scan for this E-Checklist
if (count($data) >= 9) {
  for ($x = echecklist::HOST_COL_START; $data[$x] != 'Notes'; $x++) {
    if (!preg_match("/^(\d{1,3}\.){3}(\d{1,3})$/", $data[$x])) {
      if ($pos = strpos($data[$x], '.')) {
        $data[$x] = substr($data[$x], 0, $pos);
      }
    }

    if ($id = $dbh->check_Target($conf['ste'], $data[$x])) {
      $tgt = $dbh->get_Target_Details($conf['ste'], $id)[0];
      $tgts[] = $tgt;
      //print "Identified: ".$data[$x].PHP_EOL;
    }
    else {
      $tgt = new target($data[$x]);
      $tgt->set_STE_ID($conf['ste']);
      $tgt->set_Location("New Target");
      $tgt->set_Notes("New Target");

      //print "Added target: ".$data[$x].PHP_EOL;

      if (preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $data[$x])) {
        $int = new interfaces(null, $tgt_id, null, $data[$x], null, null, null, null);
        $tgt->interfaces[] = $int;
      }

      $tgt_id = $dbh->save_Target($tgt);
      $tgts[] = $tgt;
    }

    $host_list[$tgt->get_Name()] = array('target' => $tgt, 'count' => 0);
  }

  //$host_list = substr($host_list, 0, -1);
  $dt = new DateTime();
  $existing_scan = $dbh->get_ScanData($conf['ste'], $cmd['f']);

  if (!count($existing_scan)) {
    $ste = $db->get_STE($conf['ste'])[0];
    $scan = new scan(null, $src, $ste, 1, $base_name, $dt->format('Y-m-d'));
    // $scan->add_Target_Array_to_Host_List($host_list);

    if (!$scan_id = $dbh->save_Scan($scan)) {
      $err->script_log("Failure to add scan for " . $cmd['f'], E_ERROR);
    }
    else {
      $scan->set_ID($scan_id);
    }
  }
  else {
    $scan = $existing_scan[0];
  }
}
else {
  fclose($handle);
  $err->script_log("There were less than 9 columns in " . $cmd['f'], E_ERROR);
}

$line = 0;
$line_count = 0;

while ($data = fgetcsv($handle)) {
  $line_count++;
}

// rewind after counting the lines
rewind($handle);

// skip the header lines
for ($x = 0; $x < $header_lines; $x++) {
  $data = fgetcsv($handle);
}

// loop through all the findings and add a new finding item
while ($data = fgetcsv($handle)) {
  if (empty($data[0])) {
    continue;
  }
  if (!$dbh->add_Finding($scan, $tgts, $data)) {
    $sum .= "Failure adding finding: $data[0]<br />";
    $err->script_log("Error adding STIG ID: " . $data[0], E_WARNING);
  }
  else {
    $err->script_log("Added STIG ID: " . $data[0]);
  }
  $dbh->update_Running_Scan($base_name, array('name' => 'perc_comp', 'value' => ($line / $line_count) * 100));
  $line++;
}

foreach ($tgts as $key => $tgt) {
  $host_list[$tgt->get_Name()]['count'] = $line;
}

$dbh->update_Scan_Host_List($scan, $host_list);

$count = 0;

while (is_resource($handle)) {
  if (fclose($handle)) {
    $err->script_log("File closed");
    break;
  }
  $count++;

  if ($count == 3) {
    $err->script_log("File didn't close, forcing");
    unset($handle);
    break;
  }
  sleep(1);
}

if (!isset($cmd['debug'])) {
  rename($cmd['f'], DOC_ROOT . "/tmp/echecklist/$base_name");
}

$dbh->update_Running_Scan($base_name, array('name' => 'perc_comp', 'value' => 100, 'complete' => 1));

$end = new DateTime();

print "End Time: " . $end->format("H:i:s") . PHP_EOL;

$diff = $end->diff($start);

print "Total Time: " . $diff->format("%H:%I:%S") . PHP_EOL;

function usage() {
  print <<<EOO
Purpose: To parse a CSV E-Checklist file

Usage: php parse_csv_echecklist.php -s={ST&E ID} -f={CSV eChecklist} [--debug] [--help]

 -s={ST&E ID}             The ST&E ID that this result file is going to be imported for
 -f={eChecklist file}     The eChecklist file to import

 --debug                  Debugging output
 --help                   This screen

EOO;
}
