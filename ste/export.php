<?php

/**
 * File: export.php
 * Author: Ryan Prather
 * Purpose: Export findings to an Excel spreadsheet eChecklist
 * Created: Oct 15, 2013
 *
 * Portions Copyright 2016-2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Oct 15, 2013 - File created
 *  - Dec 12, 2016 - Added Cyber Perspectives license, changed writing to spreadsheet to use constants for company data, and
 *                   Added ST&E ending date to cover page
 *  - Mar 9, 2017 - Fixed issue with export overwriting columns
 *  - Apr 15, 2017 - Set text wrapping if enabled on Short Title column
 *  - May 13, 2017 - Migrated to PHPSpreadsheet library, and add support for other export formats
 *  - Jun 3, 2017 - Fixed bug #232
 *  - Jul 23, 2017 - MAS Added comments and rudimentary RMF control support to eChecklist export
 *  - Dec 27, 2017 - Updating classification info on cover sheet page,
 *      removed classification from G2,
 *      fixed invalid function call to stringFromColumnIndex as it was moved to a different class and changed to 1-based instead of 0-based,
 *      syntax updates, updated PDF writer to Tcpdf class, added die if constant ECHECKLIST_FORMAT is not set as expected
 *  - Jan 15, 2018 - Formatting, updated use statements, not seeing behavior explained in #373
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

require_once 'vendor/autoload.php';
require_once 'excelConditionalStyles.inc';

use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
use PhpOffice\PhpSpreadsheet\Writer\Xls;
use PhpOffice\PhpSpreadsheet\Writer\Ods;
use PhpOffice\PhpSpreadsheet\Writer\Csv;
use PhpOffice\PhpSpreadsheet\Writer\Html;
use PhpOffice\PhpSpreadsheet\Cell\Coordinate;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

set_time_limit(0);
$db = new db();
$emass_ccis = null;
$log_level = convert_log_level();
$chk_hosts = filter_input_array(INPUT_POST, 'chk_host');
$cat_id = filter_input(INPUT_GET, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$cat_id) {
  $cat_id = filter_input(INPUT_POST, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}
$ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$ste_id) {
  $ste_id = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}

if (!$ste_id || !$cat_id) {
	die("Could not find the STE or Category ID");
}

$cat = $db->get_Category($cat_id)[0];
if (!is_a($cat, 'ste_cat')) {
	die("Error finding category $cat_id");
}

$ste = $db->get_STE($ste_id)[0];
if (!is_a($ste, 'ste')) {
	die("Error finding ST&E");
}

$log = new Logger("eChecklist-export");
$log->pushHandler(new StreamHandler(LOG_PATH . "/{$cat->get_Name()}-echecklist-export.log", $log_level));

if ($chk_hosts) {
  $findings = $db->get_Category_Findings($cat_id, $chk_hosts);
}
else {
  $findings = $db->get_Category_Findings($cat_id);
}
$log->debug("Got findings");

// Get mapping of eMASS controls to CCIs from DB
if ($ste->get_System()->get_Accreditation_Type() == accrediation_types::RMF) {
  $emass_ccis = $db->get_EMASS_CCIs();
}

$Reader = \PhpOffice\PhpSpreadsheet\IOFactory::createReaderForFile("eChecklist-Template.xlsx");
$ss = $Reader->load("eChecklist-Template.xlsx");

$log->debug("Loaded template");

$ss->setActiveSheetIndexByName('Cover Sheet')
   ->setCellValue("B5", "{$ste->get_System()->get_Name()} eChecklist")
   ->setCellValue("B9", "{$ste->get_Eval_Start_Date()->format("m/d/Y")}-{$ste->get_Eval_End_Date()->format("m/d/Y")}")
   ->setCellValue("B2", ($ste->get_System()->get_Classification() == 'Classified' ? "SECRET" : "UNCLASSIFIED"))
   ->setCellValue("B12", "by:\r" . COMPANY . "\r" . COMP_ADD)
   ->setCellValue("B15", "Derived from: " . SCG . "\rReasons: <reasons>\rDeclassify on: " . DECLASSIFY_ON);

// set properties
$ss->getProperties()
   ->setCreator(CREATOR);
$ss->getProperties()
   ->setLastModifiedBy(LAST_MODIFIED_BY);
$ss->getProperties()
   ->setCompany(COMPANY);
$ss->getProperties()
   ->setTitle("{$cat->get_Name()} eChecklist");
$ss->getProperties()
   ->setSubject("{$cat->get_Name()} eChecklist");
$ss->getProperties()
   ->setDescription("{$cat->get_Name()} eChecklist");

$log->debug("File properties set");

// set active sheet
$ss->setActiveSheetIndex(2);

$host_status = array(
  $conditions['open'],
  $conditions['exception'],
  $conditions['false_positive'],
  $conditions['not_a_finding'],
  $conditions['not_applicable'],
  $conditions['no_data'],
  $conditions['not_reviewed'],
  $conditions['true'],
  $conditions['false']
);

// Iterate over worksheets in the category; populating each with the checklists and finding data
foreach ($findings as $worksheet_name => $data) {
  $log->debug("Looping through worksheet $worksheet_name");
  $chk_arr = [];
  $named_range = '';

  // Build the "Checklist" cell string with titles of all checklists on this worksheet
  foreach ($data['checklists'] as $key => $chk_id) {
    $checklist = $db->get_Checklist($chk_id)[0];
    $chk_arr[] = "{$checklist->get_Name()} V{$checklist->get_Version()}R{$checklist->get_Release()} ({$checklist->get_type()})";
  }

  $checklist_str = implode(", ", $chk_arr);

  if (is_null($sheet = $ss->getSheetByName($worksheet_name))) {
    $new_sheet = clone $ss->getSheet(2);
    $new_sheet->setTitle($worksheet_name);
    $ss->addSheet($new_sheet);

    $sheet = $ss->getSheetByName($worksheet_name);

    if (is_array($data['target_list']) && count($data['target_list']) > 1) {
      $sheet->insertNewColumnBefore("G", count($data['target_list']) - 1);
    }

    $sheet->setCellValue("B9", $checklist_str);
  }
  else {
    $sheet->setCellValue("B9", "{$sheet->getCellValue("B9")}, {$checklist_str}");
  }

  $class = 'UNCLASSIFIED';
  if (isset($data['highest_class'])) {
    switch ($data['highest_class']) {
      case 'FOUO':
        $class = 'UNCLASSIFIED//FOUO';
        break;
      case 'S':
        $class = 'SECRET';
        break;
    }
  }
  else {
    if ($ste->get_System()->get_Classification() == 'Sensitive') {
      $class = 'UNCLASSIFIED//FOUO';
    }
    elseif ($ste->get_System()->get_Classification() == 'Classified') {
      $class = 'SECRET';
    }
  }

  $log->debug("Setting classification: $class");
  $sheet->setCellValue("A1", $class)
      ->setCellValue('E2', $ste->get_System()->get_Name());

  $sheet->getStyle("A1")
      ->setConditionalStyles([$conditions['unclass_classification'], $conditions['secret_classification']]);

  $row = 11;
  $last_tgt_col = Coordinate::stringFromColumnIndex(count($data['target_list']) + 5);
  $overall_col = Coordinate::stringFromColumnIndex(count($data['target_list']) + 6);
  $same_col = Coordinate::stringFromColumnIndex(count($data['target_list']) + 7);
  $notes_col = Coordinate::stringFromColumnIndex(count($data['target_list']) + 8);
  $check_contents_col = Coordinate::stringFromColumnIndex(count($data['target_list']) + 9);

  // Iterate over checklist items ($stig_id) and populate spreadsheet with status of each
  foreach ($data['stigs'] as $stig_id => $tgt_status) {
	$log->debug("Running through STIG $stig_id", $tgt_status);
    $ia_controls_string = null;

    // If $do_rmf is set, replace CCIs w/ eMASS RMF Control and build string to
    // insert into IA Controls cell, otherwise just use CCIs.
    if ($ste->get_System()->get_Accreditation_Type() == accrediation_types::RMF) {
      $ia_controls = $tgt_status['echecklist']->get_IA_Controls();
      $rmf_controls = [];

      foreach ($ia_controls as $control) {
        // Remove 'CCI-' and leading zeros
        $id = ltrim(substr($control, strpos($control, "-") + 1), '0');
        // lookup cci in $emass_ccis
        $key = array_search($id, array_column($emass_ccis, 'id'));
        // Push the control onto $rmf_controls
        array_push($rmf_controls, $emass_ccis[$key]['control']);
      }

      $ia_controls_string = implode(" ", $rmf_controls);
    }
    else {
      $ia_controls_string = $tgt_status['echecklist']->get_IA_Controls_String();
    }

    $sheet->setCellValue("A{$row}", $stig_id)
        ->setCellValue("B{$row}", $tgt_status['echecklist']->get_VMS_ID())
        ->setCellValue("C{$row}", $tgt_status['echecklist']->get_Cat_Level_String())
        ->setCellValue("D{$row}", $ia_controls_string)
        ->setCellValue("E{$row}", deduplicateString($tgt_status['echecklist']->get_Short_Title()));
	$log->debug("Added STIG info ($stig_id), not to targets");

    foreach ($data['target_list'] as $host_name => $col_id) {
      $status = 'Not Applicable';
      if (isset($tgt_status["{$host_name}"])) {
        $status = $tgt_status["{$host_name}"];
      }

      $col = Coordinate::stringFromColumnIndex($col_id);
      $sheet->setCellValue("{$col}{$row}", $status);
      $sheet->getCell("{$col}{$row}")->setDataValidation(clone $validation['host_status']);
	  $log->debug("Set data validation for target $host_name");
    }

    $overall_str = "=IF(" .
        "COUNTIF(F{$row}:{$last_tgt_col}{$row},\"Open\")+" .
        "COUNTIF(F{$row}:{$last_tgt_col}{$row},\"Exception\")" .
        ">0,\"Open\",\"Not a Finding\")";
    $same_str = "=IF(" .
        "COUNTIF(F{$row}:{$last_tgt_col}{$row},F{$row})=" .
        "COLUMNS(F{$row}:{$last_tgt_col}{$row}), TRUE, FALSE)";

    $sheet->setCellValue($overall_col . $row, $overall_str);
    $sheet->getCell("{$col}{$row}")->setDataValidation(clone $validation['host_status']);

    $sheet->setCellValue($same_col . $row, $same_str, true)
        ->getStyle("{$same_col}11:{$same_col}{$sheet->getHighestDataRow()}")
        ->setConditionalStyles([$conditions['true'], $conditions['false']]);
    //->setDataValidation($validation['true_false']);

    $sheet->setCellValue($notes_col . $row, deduplicateString($tgt_status['echecklist']->get_Notes()))
        ->setCellValue($check_contents_col . $row, deduplicateString($tgt_status['echecklist']->get_Check_Contents()));
	$log->debug("Added remaining cells");

    $row++;
  }

  $log->debug("Completed STIG parsing");
  $sheet->getStyle("F11:" . Coordinate::stringFromColumnIndex(count($data['target_list']) + 6) . $row)
      ->setConditionalStyles($host_status);
  $sheet->getStyle("C11:C{$sheet->getHighestDataRow()}")
      ->setConditionalStyles(array($conditions['cat_1'], $conditions['cat_2'], $conditions['cat_3']));

  $sheet->getStyle("{$notes_col}11:{$notes_col}{$row}")
      ->setConditionalStyles(array(
        $conditions['open_conflict'],
        $conditions['nf_na_conflict']
  ));
  if (is_array($data['target_list']) && count($data['target_list']) > 1) {
    $sheet->getStyle("G3:{$notes_col}7")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_NONE);
    $sheet->getStyle("G2")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_NONE);
    $sheet->getStyle("G2")
        ->getFont()
        ->setBold(false);
    $sheet->getStyle("G2")
        ->getAlignment()
        ->setHorizontal(\PhpOffice\PhpSpreadsheet\Style\Alignment::HORIZONTAL_LEFT);
  }

  $sheet->getStyle("A1:{$sheet->getHighestDataColumn()}{$sheet->getHighestDataRow()}")
      ->applyFromArray($borders);
  $sheet->freezePane("A11");
  $sheet->setAutoFilter("A10:{$sheet->getHighestDataColumn()}10");

  updateHostHeader($sheet, $data['target_list'], $db);

  $log->debug("Completed worksheet $worksheet_name");
}

$ss->removeSheetByIndex(2);

$log->debug("Writing to file");

$ct = '';
$writer = null;

switch (ECHECKLIST_FORMAT) {
  case 'xlsx':
    $writer = new Xlsx($ss);
    $writer->setPreCalculateFormulas(false);
    $ct = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    break;
  case 'ods':
    $writer = new Ods($ss);
    $writer->setPreCalculateFormulas(false);
    $ct = "application/vnd.oasis.opendocument.spreadsheet";
    break;
  case 'pdf':
    \PhpOffice\PhpSpreadsheet\Settings::setPdfRendererName(PhpOffice\PhpSpreadsheet\Settings::PDF_RENDERER_TCPDF);
    $writer = new Tcpdf($ss);
    $writer->writeAllSheets();
    $ct = "application/pdf";
    break;
  case 'html':
    $writer = new Html($ss);
    $writer->writeAllSheets();
    $writer->setPreCalculateFormulas(false);
    $ct = "text/html";
    break;
  case 'xls':
    $writer = new Xls($ss);
    $writer->setPreCalculateFormulas(false);
    $ct = "application/vnd.ms-excel";
    break;
  case 'csv':
    $writer = new Csv($ss);
    $ct = "text/csv";
    break;
  default:
    die("Did not recognize eChecklist format " . ECHECKLIST_FORMAT);
}

$cat_name = str_replace(" ", "_", $cat->get_Name());
header("Content-type: $ct");
header("Content-disposition: attachment; filename='{$cat_name}-eChecklist-{$ste_id}." . ECHECKLIST_FORMAT . "'");
$writer->save("php://output");
$log->debug("Writing complete");

/**
 * Update the header on the worksheet
 *
 * @param \PhpOffice\PhpSpreadsheet\Worksheet $sheet
 * @param array:integer $tgts
 * @param db $db
 */
function updateHostHeader($sheet, $tgts, &$db) {
  global $ste_id, $log;

  $host_names = [];
  $ips = [];
  $oses = [];

  $open_cat_1 = null;
  $open_cat_2 = null;
  $open_cat_3 = null;
  $not_a_finding = null;
  $not_applicable = null;
  $not_reviewed = null;

  foreach ($tgts as $tgt_name => $col_id) {
    $log->notice("tgt_name: $tgt_name\tcol_id: $col_id");
    $tgt = $db->get_Target_Details($ste_id, $tgt_name)[0];
    $os = $db->get_Software($tgt->get_OS_ID())[0];

    $oses[] = "{$os->man} {$os->name} {$os->ver}";
    $host_names[] = $tgt->get_Name();

    if (is_array($tgt->interfaces) && count($tgt->interfaces)) {
      foreach ($tgt->interfaces as $int) {
        if (!in_array($int->get_IPv4(), ["127.0.0.1", "", "0.0.0.0", null])) {
          $ips[] = $int->get_IPv4();
          break;
        }
      }
    }

    $col = Coordinate::stringFromColumnIndex($col_id);
    $highest_row = $sheet->getHighestDataRow();

    $sheet->getColumnDimension($col)
        ->setWidth(14.14);
    $sheet->setCellValue("{$col}8", "=COUNTIFS({$col}11:{$col}{$highest_row}, \"Open\", \$C\$11:\$C\${$highest_row}, \"I\")")
        ->setCellValue("{$col}9", "=COUNTIF({$col}11:{$col}{$highest_row}, \"Not Reviewed\")")
        ->setCellValue("{$col}10", $tgt->get_Name());
    $sheet->getStyle("{$col}10")
        ->getFont()
        ->setBold(true);
    $sheet->getStyle("{$col}10")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
        ->setStartColor($GLOBALS['yellow']);

    if (!is_null($open_cat_1)) {
      $open_cat_1 .= "+";
      $open_cat_2 .= "+";
      $open_cat_3 .= "+";
      $not_a_finding .= "+";
      $not_applicable .= "+";
      $not_reviewed .= "+";
    }
    else {
      $open_cat_1 = "=";
      $open_cat_2 = "=";
      $open_cat_3 = "=";
      $not_a_finding = "=";
      $not_applicable = "=";
      $not_reviewed = "=";
    }

    $open_cat_1 .= "COUNTIFS({$col}11:{$col}{$highest_row}, \"Open\", \$C\$11:\$C\${$highest_row}, \"I\")";
    $open_cat_2 .= "COUNTIFS({$col}11:{$col}{$highest_row}, \"Open\", \$C\$11:\$C\${$highest_row}, \"II\")";
    $open_cat_3 .= "COUNTIFS({$col}11:{$col}{$highest_row}, \"Open\", \$C\$11:\$C\${$highest_row}, \"III\")";
    $not_a_finding .= "COUNTIF({$col}11:{$col}{$highest_row}, \"Not a Finding\")";
    $not_applicable .= "COUNTIF({$col}11:{$col}{$highest_row}, \"Not Applicable\")";
    $not_reviewed .= "COUNTIF({$col}11:{$col}{$highest_row}, \"Not Reviewed\")";
  }

  $overall_col = Coordinate::stringFromColumnIndex(count($tgts) + 6);
  $same_col = Coordinate::stringFromColumnIndex(count($tgts) + 7);
  $notes_col = Coordinate::stringFromColumnIndex(count($tgts) + 8);
  $check_contents_col = Coordinate::stringFromColumnIndex(count($tgts) + 9);

  $sheet->getStyle("{$overall_col}8:{$same_col}8")
      ->getFill()
      ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
      ->setStartColor($GLOBALS['orange']);
  $sheet->getStyle("{$overall_col}9:{$same_col}9")
      ->getFill()
      ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
      ->setStartColor($GLOBALS['green']);
  $sheet->getStyle("{$overall_col}10:{$same_col}10")
      ->getFill()
      ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
      ->setStartColor($GLOBALS['yellow']);
  $sheet->getStyle("{$notes_col}10:{$check_contents_col}10")
      ->getFill()
      ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
      ->setStartColor($GLOBALS['light_gray']);

  $sheet->setCellValue("{$overall_col}8", "=COUNTIF({$overall_col}11:{$overall_col}{$highest_row}, \"Open\")")
      ->setCellValue("{$overall_col}9", "=COUNTIF({$overall_col}11:{$overall_col}{$highest_row}, \"Not a Finding\")")
      ->setCellValue("{$same_col}8", "=COUNTIF({$same_col}11:{$same_col}{$highest_row}, FALSE)")
      ->setCellValue("{$same_col}9", "=COUNTIF({$same_col}11:{$same_col}{$highest_row}, TRUE)")
      ->setCellValue("E3", implode(", ", $host_names))
      ->setCellValue("E4", implode(", ", $ips))
      ->setCellValue("G4", implode(", ", array_unique($oses)))
      ->setCellValue("{$overall_col}10", "Overall Status")
      ->setCellValue("{$same_col}10", "Consistent")
      ->setCellValue("{$notes_col}10", "Notes")
      ->setCellValue("{$check_contents_col}10", "Check Contents");
  $sheet->getStyle("{$overall_col}10:{$check_contents_col}10")
      ->getFont()
      ->setBold(true);

  if (!FLATTEN) {
    $sheet->getColumnDimension($overall_col)->setVisible(false);
    $sheet->getColumnDimension($same_col)->setVisible(false);
  }

  if (WRAP_TEXT) {
    $sheet->getStyle("{$check_contents_col}11:{$check_contents_col}{$sheet->getHighestDataRow()}")
        ->getAlignment()->setWrapText(true);
    $sheet->getStyle("E11:E{$sheet->getHighestDataRow()}")
        ->getAlignment()->setWrapText(true);
  }

  $sheet->setCellValue('C2', $open_cat_1)
      ->setCellValue('C3', $open_cat_2)
      ->setCellValue('C4', $open_cat_3)
      ->setCellValue('C5', $not_a_finding)
      ->setCellValue('C6', $not_applicable)
      ->setCellValue('C7', $not_reviewed);
}

/**
 * Method to split a string into an array (by new line \n) and use array_unique to remove duplicate strings
 *
 * @param string $str
 *
 * @return string
 */
function deduplicateString($str)
{
    $ret = null;
    $ret = str_replace(["\\n", PHP_EOL], "\r", $str);
    $ret = array_unique(explode("\r", $ret));
    $ret = html_entity_decode(implode("\r", $ret));

    return $ret;
}
