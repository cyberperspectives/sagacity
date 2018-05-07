<?php
/**
 * File: parse_excel_echecklist.php
 * Author: Ryan Prather
 * Purpose: Parse the Excel version (.xlsx or .xls) of an eChecklist
 * Created: May 9, 2014
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
 *  - May 9, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter,
 * 					Updated file purpose, and functions after class merger
 *  - Jan 30, 2017 - Updated to use parse_config.ini file
 *  - Mar 3, 2017 - Converted to getmypid() method instead of using Thread class
 *  - Mar 8, 2017 - Added check for existence of {TMP}/echecklist directory and revised directories to use TMP constant
 *  - May 26, 2017 - Migrated to PHPSpreadsheet library
 *  - Aug 28, 2017 - Fixed couple minor bugs
 *  - Jan 15, 2018 - Formatting, reorganized use statements, and cleaned up
 */
$cmd = getopt("f:", ['debug::', 'help::']);
set_time_limit(0);

if (!isset($cmd['f']) || isset($cmd['help'])) {
    die(usage());
}

if (!file_exists("parse_config.ini")) {
    die("Could not find parse_config.ini configuration file");
}

$conf = parse_ini_file("parse_config.ini");

chdir($conf['doc_root']);

include_once 'config.inc';
require_once "database.inc";
require_once 'helper.inc';
require_once 'vendor/autoload.php';
include_once 'excelConditionalStyles.inc';

use PhpOffice\PhpSpreadsheet\Cell\Coordinate;
use PhpOffice\PhpSpreadsheet\Worksheet\Worksheet;

check_path(TMP . "/echecklist");
chdir(TMP);

$db        = new db();
$base_name = basename($cmd['f']);
$log       = new Sagacity_Error($cmd['f']);

if (!file_exists($cmd['f'])) {
    $db->update_Running_Scan($base_name, ['name' => 'status', 'value' => 'ERROR']);
    $log->script_log("File not found", E_ERROR);
}

$db->update_Running_Scan($base_name, ['name' => 'pid', 'value' => getmypid()]);

$src = $db->get_Sources("eChecklist");
if (is_array($src) && count($src) && isset($src[0]) && is_a($src[0], 'source')) {
    $src = $src[0];
}
else {
    $log->script_log("Could not find the source", E_ERROR);
}

/*
  $cacheMethod = \PhpOffice\PhpSpreadsheet\Collection\CellsFactory::cache_to_sqlite;
  $cacheSettings = [
  'memoryCacheSize' => '512MB'
  ];
  \PhpOffice\PhpSpreadsheet\Settings::setCacheStorageMethod($cacheMethod, $cacheSettings);
 */
$host_list     = [];
$Reader        = \PhpOffice\PhpSpreadsheet\IOFactory::createReaderForFile($cmd['f']);
$Reader->setReadDataOnly(true);
$objSS         = $Reader->load($cmd['f']);
$dt            = new DateTime();
$existing_scan = $db->get_ScanData($conf['ste'], $base_name);

if (is_array($existing_scan) && count($existing_scan) && isset($existing_scan[0]) && is_a($existing_scan[0], 'scan')) {
    $scan = $existing_scan[0];
}
else {
    $ste = $db->get_STE($conf['ste']);
    if (is_array($ste) && count($ste) && isset($ste[0]) && is_a($ste[0], 'ste')) {
        $ste = $ste[0];
    }
    else {
        $log->script_log("Could not retrieve the ST&E", E_ERROR);
    }

    $scan = new scan(null, $src, $ste, 1, $base_name, $dt->format('Y-m-d'));

    if (!$scan_id = $db->save_Scan($scan)) {
        $log->script_log("Failed to add scan for file: {$cmd['f']}", E_ERROR);
    }

    $scan->set_ID($scan_id);
}

$gen_os = $db->get_Software("cpe:/o:generic:generic:-", true);
if (is_array($gen_os) && count($gen_os) && isset($gen_os[0]) && is_a($gen_os[0], 'software')) {
    $gen_os = $gen_os[0];
}

foreach ($objSS->getWorksheetIterator() as $wksht) {
    if (preg_match('/Instruction|Cover Sheet/i', $wksht->getTitle())) {
        $log->script_log("Skipping instruction and cover sheet", E_DEBUG);
        continue;
    }
    elseif (isset($conf['ignore']) && $wksht->getSheetState() == Worksheet::SHEETSTATE_HIDDEN) {
        $log->script_log("Skipping hidden worksheet {$wksht->getTitle()}");
        continue;
    }

    $db->help->select("scans", ['status'], [
        [
            'field' => 'id',
            'op'    => '=',
            'value' => $scan->get_ID()
        ]
    ]);
    $thread_status = $db->help->execute();
    if ($thread_status['status'] == 'TERMINATED') {
        unset($objSS);
        rename(realpath(TMP . "/{$scan->get_File_Name()}"), TMP . "/terminated/{$scan->get_File_Name()}");
        $log->script_log("File parsing terminated by user");
    }

    $log->script_log("Reading from {$wksht->getTitle()} worksheet");

    if (!preg_match('/STIG ID/i', $wksht->getCell("A10")->getValue()) &&
        !preg_match('/VMS ID/i', $wksht->getCell("B10")->getValue()) &&
        !preg_match('/CAT/i', $wksht->getCell("C10")->getValue()) &&
        !preg_match('/IA Controls/i', $wksht->getCell("D10")->getValue()) &&
        !preg_match('/Short Title/i', $wksht->getCell("E10")->getValue())) {
        $log->script_log("Invalid headers in {$wksht->getTitle()}", E_WARNING);
        continue;
    }

    $idx             = [
        'stig_id'        => 1,
        'vms_id'         => 2,
        'cat_lvl'        => 3,
        'ia_controls'    => 4,
        'short_title'    => 5,
        'target'         => 6,
        'overall'        => 7, // min col
        'consistent'     => 8,
        'notes'          => 9,
        'check_contents' => 10
    ];
    $finding_count   = [];
    $tgts            = [];
    $short_title_col = Coordinate::stringFromColumnIndex($idx['short_title']);
    $row_count       = $wksht->getHighestDataRow() - 10;

    foreach ($wksht->getRowIterator(10) as $row) {
        foreach ($row->getCellIterator() as $cell) {
            $ip            = null;
            $db->help->select("scans", ['status'], [
                [
                    'field' => 'id',
                    'op'    => '=',
                    'value' => $scan->get_ID()
                ]
            ]);
            $thread_status = $db->help->execute();
            if ($thread_status['status'] == 'TERMINATED') {
                unset($objSS);
                rename(realpath(TMP . "/{$scan->get_File_Name()}"), TMP . "/terminated/{$scan->get_File_Name()}");
                $log->script_log("File parsing terminated by user");
                die;
            }

            if ($cell->getColumn() > $short_title_col && !preg_match('/Overall/i', $cell->getValue())) {
                if (preg_match('/status/i', $cell->getValue())) {
                    $log->script_log("Error: Invalid host name ('status') in {$wksht->getTitle()}", E_WARNING);
                    break;
                }

                if ($tgt_id = $db->check_Target($conf['ste'], $cell->getValue())) {
                    $tgt = $db->get_Target_Details($conf['ste'], $tgt_id);
                    if (is_array($tgt) && count($tgt) && isset($tgt[0]) && is_a($tgt[0], 'target')) {
                        $tgt = $tgt[0];
                    }
                    else {
                        $log->script_log("Could not find host {$cell->getValue()}", E_ERROR);
                    }
                }
                else {
                    $tgt = new target($cell->getValue());
                    $tgt->set_OS_ID($gen_os->get_ID());
                    $tgt->set_STE_ID($conf['ste']);
                    $tgt->set_Location($conf['location']);
                    $tgt->set_Notes('New Target');

                    if (preg_match('/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}/', $cell->getValue())) {
                        $ip                       = $cell->getValue();
                        $int                      = new interfaces(null, null, null, $ip, null, null, null, null);
                        $tgt->interfaces["{$ip}"] = $int;
                    }

                    $tgt->set_ID($db->save_Target($tgt));
                }

                $tgts[] = $tgt;

                $hl = new host_list();
                $hl->setFindingCount($row_count);
                $hl->setTargetId($tgt->get_ID());
                $hl->setTargetName($tgt->get_Name());
                if ($ip) {
                    $hl->setTargetIp($ip);
                }
                elseif (is_array($tgt->interfaces) && count($tgt->interfaces)) {
                    foreach ($tgt->interfaces as $int) {
                        if (!in_array($int->get_IPv4(), ['0.0.0.0', '127.0.0.1'])) {
                            $ip = $int->get_IPv4();
                            break;
                        }
                    }
                    $hl->setTargetIp($ip);
                }

                $scan->add_Target_to_Host_List($hl);
            }

            if (preg_match('/Overall/i', $cell->getValue())) {
                break;
            }
        }
        break;
    }

    $db->update_Running_Scan($base_name, ['name' => 'host_count', 'value' => count($tgts)]);

    // increment the column indexes for notes, check contents, and missing PDI
    if (is_array($tgts) && count($tgts) > 1) {
        $idx['overall']        += count($tgts);
        $idx['consistent']     += count($tgts);
        $idx['notes']          += count($tgts);
        $idx['check_contents'] += count($tgts);
    }
    elseif (empty($tgts)) {
        $log->script_log("Failed to identify targets in worksheet {$wksht->getTitle()}", E_WARNING);
        continue;
    }

    $stig_col  = Coordinate::stringFromColumnIndex($idx['stig_id']);
    $vms_col   = Coordinate::stringFromColumnIndex($idx['vms_id']);
    $cat_col   = Coordinate::stringFromColumnIndex($idx['cat_lvl']);
    $ia_col    = Coordinate::stringFromColumnIndex($idx['ia_controls']);
    $title_col = Coordinate::stringFromColumnIndex($idx['short_title']);
    $notes_col = Coordinate::stringFromColumnIndex($idx['notes']);

    $new_findings     = [];
    $updated_findings = [];

    foreach ($wksht->getRowIterator(11) as $row) {
        $stig_id     = $wksht->getCell("{$stig_col}{$row->getRowIndex()}")->getValue();
        $cat_lvl     = substr_count($wksht->getCell("{$cat_col}{$row->getRowIndex()}")->getValue(), "I");
        $short_title = $wksht->getCell("{$title_col}{$row->getRowIndex()}")->getValue();
        $notes       = $wksht->getCell("{$notes_col}{$row->getRowIndex()}")->getValue();

        $stig = $db->get_Stig($stig_id);

        if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
            $stig = $stig[0];
        }
        else {
            $pdi    = new pdi(null, $cat_lvl, $dt->format("Y-m-d"));
            $pdi->set_Short_Title($short_title);
            $pdi->set_Group_Title($short_title);
            if (!($pdi_id = $db->save_PDI($pdi))) {
                $log->script_log("Failed to add a new PDI for STIG ID $stig_id", E_ERROR);
            }

            $stig = new stig($pdi_id, $stig_id, $short_title);
            $db->add_Stig($stig);
        }

        $x = 0;
        foreach ($tgts as $tgt) {
            $status = $wksht->getCell(Coordinate::stringFromColumnIndex($idx['target'] + $x) . $row->getRowIndex())
                ->getValue();

            $log->script_log("{$tgt->get_Name()} {$stig->get_ID()} ($status)\n", E_DEBUG);

            $finding = $db->get_Finding($tgt, $stig);

            if (is_array($finding) && count($finding) && isset($finding[0]) && is_a($finding[0], 'finding')) {
                $tmp = $finding[0];

                $tmp->set_Finding_Status_By_String($status);
                $tmp->set_Notes($notes);
                $tmp->set_Category($cat_lvl);

                $updated_findings[] = $tmp;
            }
            else {
                $tmp = new finding(null, $tgt->get_ID(), $stig->get_PDI_ID(), $scan->get_ID(), $status, $notes, null, null, null);
                $tmp->set_Category($cat_lvl);

                $new_findings[] = $tmp;
            }

            $x++;
        }

        if (PHP_SAPI == 'cli') {
            print "\r" . sprintf("%.2f%%", (($row->getRowIndex() - 10) / $row_count) * 100);
        }
        else {
            $db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => (($row->getRowIndex() - 10) / $row_count) * 100]);
        }
    }

    if (!$db->add_Findings_By_Target($updated_findings, $new_findings)) {
        print "Error adding finding" . PHP_EOL;
    }
}

unset($objSS);
$db->update_Scan_Host_List($scan, $host_list);
if (!isset($cmd['debug'])) {
    rename($cmd['f'], TMP . "/echecklist/$base_name");
}
$db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => 100, 'complete' => 1]);

function usage()
{
    print <<<EOO
Purpose: To import an Excel E-Checklist file.

Usage: php parse_excel_echecklist.php -f={eChecklist File} [-i] [--debug] [--help]

 -f={eChecklist File}     The file to import
 -i                       Ignore hidden worksheets.  This run by default when run through Sagacity

 --debug                  Debugging output
 --help                   This screen

EOO;
}

/**
 * Function to validate and make sure spreadsheet is as it should be
 *
 * @param \PhpOffice\PhpSpreadsheet\Worksheet\Worksheet $wksht
 */
function check_worksheet(\PhpOffice\PhpSpreadsheet\Worksheet\Worksheet &$wksht)
{

}
