<?php

/**
 * File: populate_cve_web.php
 * Author: Ryan Prather
 * Purpose: Find all CVE files, read entire file and add to database for later retrieval
 * Created: Sep 1, 2016
 *
 * Portions Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 1, 2016 - File created
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$db = new mysqli(DB_SERVER, "web", db::decrypt_pwd());

set_time_limit(0);

$files = glob("../reference/cve/*.xml");

$count = 0;
$start_sql = $sql = "INSERT IGNORE INTO `reference`.`cve_web` (`cve_id`,`xml`) VALUES ";

foreach ($files as $file) {
  print ".";
  $xml = new DOMDocument();
  $xml->load($file);

  $cve_id = getValue($xml, "/item/@name");
  if (empty($cve_id)) {
    die;
  }

  $sql .= "(" .
      "'" . $db->real_escape_string($cve_id) . "'," .
      "'" . $db->real_escape_string($xml->saveXML()) . "'),";

  $count++;

  if ($count % 100 == 0 || strlen($sql) > 5000000) {
    if (!$db->real_query(substr($sql, -1))) {
      error_log($db->error);
      Sagacity_Error::sql_handler($sql);
      die;
    }
    print "\t$count\t" . strlen($sql) . PHP_EOL;
    $sql = $start_sql;
  }
}