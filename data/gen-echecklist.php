<?php

set_time_limit(0);
require_once 'config.inc';
require_once 'helper.inc';
require_once 'vendor/autoload.php';
require_once 'database.inc';
require_once 'excelConditionalStyles.inc';

use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$log_level = convert_log_level();
$log = new Logger("eChecklist-export");
$log->pushHandler(new StreamHandler(LOG_PATH . "/echecklist-export.log", $log_level));

global $conditions, $validation, $borders;

$db = new db();
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

if(!$id) {
    die("Failed to read checklist ID");
}

$host_status = [
    $conditions['open'],
    $conditions['exception'],
    $conditions['false_positive'],
    $conditions['not_a_finding'],
    $conditions['not_applicable'],
    $conditions['no_data'],
    $conditions['not_reviewed'],
    $conditions['true'],
    $conditions['false']
];

/** @var checklist $chk */
$chk = $db->get_Checklist($id);
if(is_array($chk) && count($chk) && isset($chk[0])) {
    $chk = $chk[0];
} else {
    die("Failed to find the checklist");
}

$Reader = \PhpOffice\PhpSpreadsheet\IOFactory::createReaderForFile("../ste/eChecklist-Template.xlsx");
$ss = $Reader->load("../ste/eChecklist-Template.xlsx");

$log->debug("Loaded template");

$ss->setActiveSheetIndexByName('Cover Sheet')
    ->setCellValue("B5", "{$chk->get_Name()} eChecklist")
    ->setCellValue("B9", "")
    ->setCellValue("B2", (substr($chk->get_File_Name(), 0, 1) == 'U' ? "UNCLASSIFIED" : "FOUO"))
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
    ->setTitle("{$chk->get_Name()} eChecklist");
$ss->getProperties()
    ->setSubject("{$chk->get_Name()} eChecklist");
$ss->getProperties()
    ->setDescription("{$chk->get_Name()} eChecklist");

// set active sheet
$ss->setActiveSheetIndex(2);
$sheet = $ss->getActiveSheet();
$sheet->setCellValue("B9", "{$chk->get_Name()} V{$chk->get_Version()}R{$chk->get_Release()} ({$chk->get_type()})");
$sheet->setTitle($chk->get_Name());
$sheet->setCellValue("A1", (substr($chk->get_File_Name(), 0, 1) == 'U' ? "UNCLASSIFIED" : "UNCLASSIFIED//FOUO"));

$db->help->select("pdi", null, [
    [
        'field' => 'pcl.checklist_id',
        'op' => '=',
        'value' => $id
    ]
], [
    'table_joins' => [
        "JOIN pdi_checklist_lookup pcl ON pcl.pdi_id = pdi.pdi_id"
    ]
]);
$pdis = $db->help->execute();

$row = 11;
if(is_array($pdis) && count($pdis)) {
    foreach($pdis as $p) {
        $overall_str = "=IF(" .
            "COUNTIF(F{$row}:F{$row},\"Open\")+" .
            "COUNTIF(F{$row}:F{$row},\"Exception\")" .
            ">0,\"Open\",\"Not a Finding\")";
        $same_str = "=IF(" .
            "COUNTIF(F{$row}:F{$row},F{$row})=" .
            "COLUMNS(F{$row}:F{$row}), TRUE, FALSE)";
        
        $sheet->setCellValue("A{$row}", $p['STIG_ID'])
            ->setCellValue("B{$row}", $p['VMS_ID'])
            ->setCellValue("C{$row}", $p['CAT'])
            ->setCellValue("D{$row}", $p['IA_Controls'])
            ->setCellValue("E{$row}", $p['short_title'])
            ->setCellValue("F{$row}", "Not Reviewed")
            ->setCellValue("G{$row}", $overall_str)
            ->setCellValue("H{$row}", $same_str, true)
            ->setCellValue("I{$row}", "")
            ->setCellValue("J{$row}", $p['check_contents'])
            ->getStyle("H11:H{$sheet->getHighestDataRow()}")
            ->setConditionalStyles([$conditions['true'], $conditions['false']]);
        $row++;
    }
    
    $sheet->setDataValidation("F11:F{$row}", clone $validation['host_status']);
    $sheet->getStyle("F11:G{$row}")
        ->setConditionalStyles($host_status);
    $sheet->getStyle("C11:C{$row}")
        ->setConditionalStyles(array($conditions['cat_1'], $conditions['cat_2'], $conditions['cat_3']));
    
    $sheet->getStyle("I11:I{$row}")
        ->setConditionalStyles(
        [
            $conditions['open_conflict'],
            $conditions['nf_na_conflict']
        ]
    );
    
    $sheet->getStyle("A1:I{$row}")
        ->applyFromArray($borders);
    $sheet->freezePane("A11");
    $sheet->setAutoFilter("A10:I10");
    
    $sheet->getColumnDimension("F")->setWidth(14.14);
    $sheet->setCellValue("F8", "=COUNTIFS(F11:F{$row}, \"Open\", \$C\$11:\$C\${$row}, \"I\")")
        ->setCellValue("F9", "=COUNTIF(F11:F{$row}, \"Not Reviewed\")")
        ->setCellValue("F10", "Example");
    $sheet->getStyle("F10")
        ->getFont()
        ->setBold(true);
    $sheet->getStyle("F10")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
        ->setStartColor($GLOBALS['yellow']);

    $open_cat_1 = "=COUNTIFS(F11:F{$row}, \"Open\", \$C\$11:\$C\${$row}, \"I\")";
    $open_cat_2 = "=COUNTIFS(F11:F{$row}, \"Open\", \$C\$11:\$C\${$row}, \"II\")";
    $open_cat_3 = "=COUNTIFS(F11:F{$row}, \"Open\", \$C\$11:\$C\${$row}, \"III\")";
    $not_a_finding = "=COUNTIF(F11:F{$row}, \"Not a Finding\")";
    $not_applicable = "=COUNTIF(F11:F{$row}, \"Not Applicable\")";
    $not_reviewed = "=COUNTIF(F11:F{$row}, \"Not Reviewed\")";
    
    $sheet->getStyle("G8:H8")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
        ->setStartColor($GLOBALS['orange']);
    $sheet->getStyle("G9:H9")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
        ->setStartColor($GLOBALS['green']);
    $sheet->getStyle("G10:H10")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
        ->setStartColor($GLOBALS['yellow']);
    $sheet->getStyle("I10:J10")
        ->getFill()
        ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)
        ->setStartColor($GLOBALS['light_gray']);
    
    $sheet->setCellValue("G8", "=COUNTIF(G11:H{$row}, \"Open\")")
        ->setCellValue("G9", "=COUNTIF(G11:G{$row}, \"Not a Finding\")")
        ->setCellValue("H8", "=COUNTIF(H11:H{$row}, FALSE)")
        ->setCellValue("H9", "=COUNTIF(H11:H{$row}, TRUE)")
        ->setCellValue("E3", "")
        ->setCellValue("E4", "")
        ->setCellValue("G4", "")
        ->setCellValue('C2', $open_cat_1)
        ->setCellValue('C3', $open_cat_2)
        ->setCellValue('C4', $open_cat_3)
        ->setCellValue('C5', $not_a_finding)
        ->setCellValue('C6', $not_applicable)
        ->setCellValue('C7', $not_reviewed);
        
} else {
    print "Error";
}

/**/
$writer = new Xlsx($ss);
$writer->setPreCalculateFormulas(false);
header("Content-type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
header("Content-disposition: attachment; filename='{$chk->get_Name()}-eChecklist.xlsx'");
$writer->save("php://output");
