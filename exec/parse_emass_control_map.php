<?php

/**
 * File: parse_emass_control_map.php
 * Author: Matt Shuter
 * Purpose: Parse the Excel mapping of eMASS controls (.xlsx or .xls) into the database
 * Created: Jul 6, 2017
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
 *  - Jul 6, 2017 - File created
 */
$cmd = getopt("f:", ['debug::', 'help::']);
set_time_limit(0);

//use \PhpOffice\PhpSpreadsheet\Cell;

if (!isset($cmd['f']) || isset($cmd['help'])) {
  die(usage());
}
elseif (!file_exists($cmd['f'])) {
  die("File {$cmd['f']} not found" . PHP_EOL);
}

include_once 'config.inc';
require_once "database.inc";
require_once 'helper.inc';

require_once 'vendor/autoload.php';


check_path(TMP . "/rmf");
chdir(TMP);

$base_name = basename($cmd['f']);
$err = new Sagacity_Error($cmd['f']);
$db = new db();

// Create reader for file
$Reader = \PhpOffice\PhpSpreadsheet\IOFactory::createReaderForFile($cmd['f']);
$Reader->setReadDataOnly(true);
$objSS = $Reader->load($cmd['f']);

// Get the first and only worksheet
$wksht = $objSS->getSheet(0);

$col1 = true;     // Bool to determine which column we're in within the loop
$ccis = array();    // Array to hold cci-control mappings
// Main loop to read in the Excel spreadsheet
foreach ($wksht->getRowIterator() as $row) {
  foreach ($row->getCellIterator() as $cell) {
    if ($col1) { // First column is the control
      $ctrl = $cell->getValue();
    }
    else { // Second column is the cci
      $cci = $cell->getValue();
    }
    // Change the col1 to iterate between the two columns
    $col1 = !$col1;
  }

  $cci_id = substr($cci, strpos($cci, "-") + 1);

  array_push($ccis, array($cci_id, $ctrl));
}

$db->save_EMASS_CCIs($ccis);

unset($objSS);
if (!isset($cmd['debug'])) {
  rename($cmd['f'], TMP . "/rmf/$base_name");
}

function usage() {
  print <<<EOO
Purpose: To import an Excel eMASS-CCI control mapping spreadsheet.

Usage: php parse_emass_control_map.php -f={Excel control map file} [--debug] [--help]

 -f={Excel filename}	  File to import
 --debug                  Debugging output
 --help                   This screen

EOO;
}
