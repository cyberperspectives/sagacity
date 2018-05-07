<?php

/**
 * File: parse_cce.php
 * Author: Ryan Prather
 * Purpose: Read the CCE file from NIST and import all CCE's to database
 * Created: Mar 17, 2015
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
 *  - Mar 17, 2015 - File created
 *  - Sep 1, 2016 - Copyright Updated, added file purpose, and converted to use constants
 */
$cmd = getopt("f:", array("debug::", "help::"));

if (!isset($cmd['f']) || isset($cmd['help'])) {
  usage();
  exit;
}

include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';
include_once 'xml_parser.inc';

chdir(DOC_ROOT . "/tmp");
set_time_limit(0);

class cce_parser extends basic_xml_parser {

  var $sql;
  var $count;
  var $cce;

  public function __construct($xml_fname) {
    parent::__construct($this, $xml_fname);
    $this->sql = "INSERT IGNORE INTO `targets`.`software` (`cpe`,`cpe23`,`sw_string`) VALUES ";
    $this->count = 0;
    $this->db = new mysqli(DB_SERVER, "web", db::decrypt_pwd());
  }

  public function cce_cce_list_cces_cce($attrs) {

  }

}

$parser = new cce_parser($cmd['f']);
$parser->debug = (isset($cmd['debug']) ? true : false);
$parser->parse();

function usage() {
  print <<<EOO
Purpose: To read a CCE list, parse it, and populate/update the database

Usage: php parse_cce.php -f={cce list file} [--debug] [--help]

 -f={cce file}      The CCE list file retrieved from http://static.nvd.nist.gov/feeds/xml/cce/cce-COMBINED-5.20130214.xml

 --debug            Debugging output
 --help             This screen

EOO;
}
