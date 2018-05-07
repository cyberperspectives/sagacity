<?php

/**
 * File: parse_procedurals.php
 * Purpose: Script to populate procedural database tables from Excel file
 * Author: Ryan Prather
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
 *  - Sep 1, 2016 - Copyright Updated, added file header, and
 * 					converted to constants
 */
$cmd = getopt("", array('debug::', "help::"));

if (isset($cmd['help'])) {
  usage();
  exit;
}

include_once 'config.inc';
require_once 'PHPExcel.php';
include_once 'helper.inc';

$db = new mysqli(DB_SERVER, 'web', db::decrypt_pwd());
if ($db->connect_error) {
  print $db->connect_error;
  die;
}

$cacheMethod = PHPExcel_CachedObjectStorageFactory::cache_to_sqlite;
$cacheSettings = array(
  'memoryCacheSize' => '512MB'
);
PHPExcel_Settings::setCacheStorageMethod($cacheMethod, $cacheSettings);
$Reader = PHPExcel_IOFactory::createReaderForFile("8500.2_IA_Controls_and_Validation_Procedures.xls");
$Reader->setReadDataOnly(true);
$objPHPExcel = $Reader->load("8500.2_IA_Controls_and_Validation_Procedures.xls");
if (false) {
  $objPHPExcel = PHPExcel_IOFactory::load("8500.2_IA_Controls_and_Validation_Procedures.xls");
}

$wksht = $objPHPExcel->getSheetByName("All 8500.2 IA Controls");
$lastrow = $wksht->getHighestDataRow();
for ($row = 2; $row <= $lastrow; $row++) {
  $ia_id = $wksht->getCell("A$row")->getValue();
  $name = htmlentities($wksht->getCell("B$row")->getValue());
  $sub = $wksht->getCell("C$row")->getValue();
  $desc = htmlentities($wksht->getCell("D$row")->getValue());
  $tvcm = htmlentities($wksht->getCell("E$row")->getValue());
  $gen_guide = htmlentities($wksht->getCell("F$row")->getValue());
  $sys_spec = htmlentities($wksht->getCell("G$row")->getValue());
  $impact = strtolower($wksht->getCell("H$row")->getValue());

  $sql = "REPLACE INTO sagacity.proc_ia_controls (control_id, `name`, subject_area, description, threat_vul_cm, gen_imp_guide, guide_resource, impact) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  if (!$sth = $db->prepare($sql)) {
    error_log($db->error);
    continue;
  }
  $sth->bind_param('ssssssss', $ia_id, $name, $sub, $desc, $tvcm, $gen_guide, $sys_spec, $impact);
  $sth->execute();
  $sth->close();

  $sql = "REPLACE INTO sagacity.proc_level_type (proc_control, `type`, level, class) VALUES (?, ?, ?, ?)";
  if (!$sth = $db->prepare($sql)) {
    error_log($db->error);
    continue;
  }

  $control_type = 'diacap';

  for ($idx = 8; ($col = PHPExcel_Cell::stringFromColumnIndex($idx)) < 'R'; $idx++) {
    $val = $wksht->getCell($col . $row)->getValue();
    $head = $wksht->getCell($col . "1")->getValue();
    if ($val == 'Y') {
      $type = explode(' - ', $head);
      $lvl = substr_count($type[0], 'I');
      switch ($type[1]) {
        case 'CL':
          $class = 'cl';
          break;
        case 'S':
          $class = 'sen';
          break;
        case 'P':
          $class = 'pub';
          break;
      }

      $sth->bind_param('ssss', $ia_id, $control_type, $lvl, $class);
      $sth->execute();
    }
  }

  $sth->close();
}

$wksht = $objPHPExcel->getSheetByName("All Validation Procedures");
$lastrow = $wksht->getHighestDataRow();
for ($row = 2; $row <= $lastrow; $row++) {
  $parent_id = $wksht->getCell("A$row")->getValue();
  $sub_id = $wksht->getCell("B$row")->getValue();
  $name = htmlentities($wksht->getCell("C$row")->getValue());
  $obj = htmlentities($wksht->getCell("D$row")->getValue());
  $prep = htmlentities($wksht->getCell("E$row")->getValue());
  $script = htmlentities($wksht->getCell("F$row")->getValue());
  $exp = htmlentities($wksht->getCell("G$row")->getValue());

  $sql = "REPLACE INTO sagacity.proc_ia_sub_controls (sub_control_id, parent_control_id, `name`, objective, prep, `script`, exp_result) VALUES (?, ?, ?, ?, ?, ?, ?)";

  if (!$sth = $db->prepare($sql)) {
    error_log($db->error);
    continue;
  }

  $sth->bind_param('sssssss', $sub_id, $parent_id, $name, $obj, $prep, $script, $exp);
  $sth->execute();
  $sth->close();
}

function usage() {
  print <<<EOO
Purpose: To import the DIACAP IA control library

Usage: php parse_procedurals.php [--help]

 --help             This screen

EOO;
}
