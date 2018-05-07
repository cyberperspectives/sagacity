<?php

/**
 * File: parse_cci.php
 * Author: Ryan Prather
 * Purpose: Script to parse CCI library
 * Created: Jul 28, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jul 28, 2014 - File created
 */
$cmd = getopt("f:", array('debug::', "help::"));

if (!isset($cmd['f']) || isset($cmd['help'])) {
  usage();
  exit;
}

include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

chdir(DOC_ROOT);

set_time_limit(0);

$base_name = basename($cmd['f']);
$db = new db();
$err = new Sagacity_Error($cmd['f']);
$match = array();

if (!file_exists($cmd['f'])) {
  $err->script_log("File not found", E_ERROR);
}

$xml = new DOMDocument();
if (!$xml->load($cmd['f'])) {
  $err->script_log("There was an issue loading XML document", E_ERROR);
}

$cci_list = getValue($xml, "/root/cci", null, true);

print "Reading $cci_list->length CCIs" . PHP_EOL;

$all_ccis = array();

foreach ($cci_list as $cci_node) {
  $cci = new cci();
  $cci->cci_id = preg_replace("/CCI\-[0]+/", "", $cci_node->getAttribute("id"));

  if ($cci->cci_id > 3391) {
    break;
  }

  $control = getValue($xml, "control", $cci_node);
  $cci->control_id = preg_replace("/ \(\d+\)/", "", $control);
  $cci->definition = getValue($xml, "definition", $cci_node);
  $cci->guidance = getValue($xml, "guidance", $cci_node);
  $cci->procedure = getValue($xml, "procedure", $cci_node);

  if (preg_match("/ \(([\d]+)\)/", getValue($xml, "control", $cci_node), $match)) {
    $cci->enh_id = $match[1];
  }
  else {
    $cci->enh_id = null;
  }

  $all_ccis[] = $cci;

  print "$cci->cci_id" . PHP_EOL;

  if (count($all_ccis) == 100) {
    print "Saving 100 CCI's" . PHP_EOL;
    $db->save_CCI($all_ccis);
    $all_ccis = array();
  }
}
//die;
print "Saving..." . PHP_EOL;
$db->save_CCI($all_ccis);
print "Done saving " . count($all_ccis) . " CCIs" . PHP_EOL;

function usage() {
  print <<<EOO
Purpose: To parse the NIST CCI list

Usage: php parse_cci.php -f={CCI list file} [--debug] [--help]

 -f={CCI file}      The CCI file to parse

 --debug            Debugging output
 --help             This screen

EOO;
}
