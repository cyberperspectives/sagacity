<?php

/**
 * File: post_process_all.php
 * Author: Jeff Odegard
 * Purpose: Script to perform bulk post-processing on all targets or all targets in a specific ST&E
 * Created: May 19,2015
 *
 * Portions Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - May 19, 2015 - File created
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$cmd = getopt("h::", array("help::", "ste::", "debug::"));

if (isset($cmd['h']) || isset($cmd['help'])) {
  usage();
  exit;
}

$db = new db();

if (isset($cmd['ste'])) {
  $tgts = $db->get_Target_Details($cmd['ste']);

  foreach ($tgts as $key => $tgt) {
    print "Post-processing " . $tgt->get_Name() . PHP_EOL;
    $db->post_Processing($tgt->get_ID());
  }
}
else {
  $db->post_Processing();
}

function usage() {
  print <<<EOO
Purpose: Perform bulk post-processing

Usage: php post_process_all.php [--ste={ST&E ID}] [--help|-h] [--debug]

   NOTE: If no ST&E specified then will get all targets that have the pp_flag field in the database set to '1'

 --ste={ST&E ID}    The ST&E ID to evaluate targets

 --debug            Debugging output
 --help | -h        This screen

EOO;
}
