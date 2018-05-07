<?php

/**
 * File: script_header.inc
 * Author: Ryan Prather
 * Purpose: To standardize the header for any script that has to parse files
 * Created: ?
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - ? - File created
 *  - Sep 1, 2016 - Copyright updated and added file header
 */
$start = new DateTime();

$cmd = getopt("f:s::", array('debug::'));

set_time_limit(0);
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

chdir(TMP);

$db = new db();
$base_name = basename($cmd['f']);

$log = new Sagacity_Error($base_name);

if (!file_exists($cmd['f'])) {
  $db->update_Running_Scan($base_name, array('name' => 'status', 'value' => 'ERROR'));
  $err->script_log("File not found", E_ERROR);
}

$db->update_Running_Scan($base_name, array('name' => 'pid', 'value' => getmypid()));
