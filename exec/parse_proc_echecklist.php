<?php

/**
 * File: parse_proc_echecklist.php
 * Author: Ryan Prather
 * Purpose: Script to import a procedural eChecklist
 * Created: Feb 23, 2015
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
 *  - Feb 23, 2015 - File created
 *  - Sep 1, 2016 - Copyright and file purpose updated
 */
$cmd = getopt("s:f:", array("debug::", "help::"));

if (!isset($cmd['s']) || !isset($cmd['f']) || isset($cmd['help'])) {
  usage();
  exit;
}

function usage() {
  print <<<EOO
Purpose: To import a procedural eChecklist file that is filled out

Usage: php parse_proc_echecklist.php -s={ST&E ID} -f={Procedural eChecklist File} [--debug] [--help]

 -s={ST&E ID}       The ST&E ID this result file is being imported for
 -f={file}          The file to import

 --debug            Debugging output
 --help             This screen

EOO;
}
