<?php

/**
 * File: nessus-plugin-import.php
 * Author: Ryan Prather
 * Purpose: Script to import all Nessus plugins from *.nasl files
 * Created: Jan 5, 2015
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
 *  - Jan 5, 2015 - File created
 *  - Sep 1, 2016 - Copyright updated, converted to constants, and added file header
 *  - Jan 30, 2017 - Updated for platform independence and formatting
 *  - Jan 31, 2017 - Completed testing, ready for prime time
 *  - Feb 15, 2017 - Store existing plugin IDs in memory for evaluation to check if we should actually run the script,
 *                   Fixed error with PHP_BIN not being defined for some weird reason
 */
include_once 'config.inc';
include_once "database.inc";
include_once "helper.inc";

$cmd = getopt("h::", array("help::"));

if (isset($cmd['h']) || isset($cmd['help'])) {
  die(usage());
}

$db = new db();

if (!file_exists(TMP . "/nessus_plugins")) {
  mkdir(TMP . "/nessus_plugins");
}

$nasl_ids = array();
$db->help->select("sagacity.nessus_plugins", array('plugin_id', 'file_date'));
if ($rows = $db->help->execute()) {
  foreach ($rows as $row) {
    $nasl_ids[$row['plugin_id']] = DateTime::createFromFormat("U", $row['file_date']);
  }
}

chdir(TMP . '/nessus_plugins');
$files = glob("*.nasl");

$start_time = new DateTime();

print "Found " . count($files) . " NASL files\nStarted at {$start_time->format("Y-m-d H:i:s")}\n";

chdir(DOC_ROOT . '/exec');
$x = 0;
foreach ($files as $file) {
  $db->help->select("nessus_plugins", array('plugin_id', 'file_date'), [
    [
      'field' => 'file_name',
      'op'    => '=',
      'value' => basename($file)
    ]
  ]);
  $row = $db->help->execute();

  if (!isset($row['file_name']) || is_null($row['file_date']) || filemtime(TMP . "/nessus_plugins/$file") > $row['file_date']) {
    $comp = number_format(($x / count($files)) * 100, 2) . "%";
    print "\r$comp";

    $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
        " -c " . realpath(PHP_CONF) .
        " -f " . realpath(DOC_ROOT . "/exec/nessus-plugin-to-database.php") . " --" .
        " -f=\"" . realpath(TMP . "/nessus_plugins/$file") . "\"";

    if (substr(strtolower(PHP_OS), 0, 3) == "win") {
      $shell = new COM("WScript.Shell");
      $shell->CurrentDirectory = DOC_ROOT . "/exec";
      $shell->run($script, 0, false);
    }
    elseif (substr(strtolower(PHP_OS), 0, 3) == 'lin') {
      exec("$script > /dev/null &");

      $output = array();
      exec("netstat -an | grep TIME_WAIT | wc -l", $output);
      if ($output[0] > 1200) {
        do {
          sleep(1);
          exec("netstat -an | grep TIME_WAIT | wc -l", $output);
        }
        while ($output[0] > 100);
      }
    }

    $x++;
  }
}

$db->help->update("settings", ['meta_value' => 100], [
    [
        'field' => 'meta_key',
        'op' => IN,
        'value' => ['nasl-dl-progress', 'nasl-progress']
    ]
]);
$db->help->execute();

$end_time = new DateTime();

$diff = $end_time->diff($start_time);

print "\nFinished at {$end_time->format("Y-m-d H:i:s")}\nTotal Time: {$diff->format("%H:%I:%S")}\n";

function usage() {
  print <<<EOF
Purpose: The purpose of this script is to update the CVE, CPE, and CCE databases.  Script will sleep for 3 seconds between actions to allow you review the results.

Usage: php nessus-plugin-import.php [-h|--help]

 -h|--help          This screen

EOF;
}
