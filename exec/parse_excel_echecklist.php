<?php
/**
 * File: parse_excel_echecklist.php
 * Author: Ryan Prather
 * Purpose: Parse the Excel version (.xlsx or .xls) of an eChecklist
 * Created: May 9, 2014
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
 *  - May 9, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter,
 * 					Updated file purpose, and functions after class merger
 *  - Jan 30, 2017 - Updated to use parse_config.ini file
 *  - Mar 3, 2017 - Converted to getmypid() method instead of using Thread class
 *  - Mar 8, 2017 - Added check for existence of {TMP}/echecklist directory and revised directories to use TMP constant
 *  - May 26, 2017 - Migrated to PHPSpreadsheet library
 *  - Aug 28, 2017 - Fixed couple minor bugs
 *  - Jan 15, 2018 - Formatting, reorganized use statements, and cleaned up
 *  - May 24, 2018 - Attempt to fix bug #413
 *  - Nov 6, 2018 - performance improvements, ensure duplicate findings are not created, make eChecklist true status, update for removing findings.id 
 *  - Nov 8, 2018 - added functionality to assign OS and checklists based on worksheet contents
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
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

check_path(TMP . "/echecklist");
chdir(TMP);
$log_level = convert_log_level();

$db        = new db();
$base_name = basename($cmd['f']);
$log	   = new Logger("excel-echecklist");
$log->pushHandler(new StreamHandler(logify($cmd['f']), $log_level));

if (!file_exists($cmd['f'])) {
    $db->update_Running_Scan($base_name, ['name' => 'status', 'value' => 'ERROR']);
	die($log->emergency("File not found"));
}

$db->update_Running_Scan($base_name, ['name' => 'pid', 'value' => getmypid()]);

$src = $db->get_Sources("eChecklist");
if (is_array($src) && count($src) && isset($src[0]) && is_a($src[0], 'source')) {
    $src = $src[0];
}
else {
	die($log->emergency("Could not find the source"));
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
		die($log->emergency("Could not retrieve ST&E"));
    }

    $scan = new scan(null, $src, $ste, 1, $base_name, $dt->format('Y-m-d'));

    if (!$scan_id = $db->save_Scan($scan)) {
		die($log->error("Failed to add scan for file: {$cmd['f']}"));
    }

    $scan->set_ID($scan_id);
}

/** @var software $gen_os */
$gen_os = $db->get_Software("cpe:/o:generic:generic:-", true);
if (is_array($gen_os) && count($gen_os) && isset($gen_os[0]) && is_a($gen_os[0], 'software')) {
    $gen_os = $gen_os[0];
}

foreach ($objSS->getWorksheetIterator() as $wksht) {
    if (preg_match('/Instruction|Cover Sheet/i', $wksht->getTitle())) {
		$log->debug("Skipping instruction and cover worksheet");
        continue;
    }
    elseif (isset($conf['ignore']) && $wksht->getSheetState() == Worksheet::SHEETSTATE_HIDDEN) {
		$log->info("Skipping hidden worksheet {$wksht->getTitle()}");
        continue;
    } elseif ($wksht->getTitle() == 'Orphan') {
        $log->info("Skipping Orphan worksheet because it creates problems right now");
        continue;
    }

    $scan->isTerminated();

	$log->notice("Reading from {$wksht->getTitle()}");

    if (!preg_match('/STIG ID/i', $wksht->getCell("A10")->getValue()) &&
        !preg_match('/VMS ID/i', $wksht->getCell("B10")->getValue()) &&
        !preg_match('/CAT/i', $wksht->getCell("C10")->getValue()) &&
        !preg_match('/IA Controls/i', $wksht->getCell("D10")->getValue()) &&
        !preg_match('/Short Title/i', $wksht->getCell("E10")->getValue())) {
			$log->warning("Invalid headers in {$wksht->getTitle()}");
        continue;
    }
    
    $chk_arr = explode(', ', $wksht->getCell("B9")->getValue());
    $checklists = $db->get_Checklist_By_Name($chk_arr);
    $os_str = $wksht->getCell("G4")->getValue();
    $os = $db->get_Software_By_String($os_str);

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
    $tgts            = [];
    $short_title_col = Coordinate::stringFromColumnIndex($idx['short_title']);
    $row_count       = $highestRow = $wksht->getHighestDataRow() - 10;
    $highestCol      = $wksht->getHighestDataColumn(10);
    $tgt_findings    = [];

    for ($col = 'F' ; $col != $highestCol ; $col++) {
        $cell = $wksht->getCell($col . '10');
        $log->debug("Checking column: {$cell->getColumn()} {$cell->getCoordinate()}");
        $ip            = null;

        $scan->isTerminated();

        if (!preg_match('/Overall/i', $cell->getValue())) {
            if (preg_match('/status/i', $cell->getValue())) {
				$log->error("Invalid host name ('status') in {$wksht->getTitle()}");
                break;
            }

            if ($tgt_id = $db->check_Target($conf['ste'], $cell->getValue())) {
                $log->debug("Found host for {$cell->getValue()}");
                /** @var target $tgt */
                $tgt = $db->get_Target_Details($conf['ste'], $tgt_id);
                if (is_array($tgt) && count($tgt) && isset($tgt[0]) && is_a($tgt[0], 'target')) {
                    $tgt = $tgt[0];
                    if($tgt->get_OS_ID() == $gen_os->get_ID() && is_a($os, 'software')) {
                        $log->debug("Assigning operating system to {$tgt->get_Name()}", [$os]);
                        $tgt->set_OS_ID($os->get_ID());
                        $tgt->set_OS_String($os->get_Shortened_SW_String());
                    }
                }
                else {
					$log->error("Could not find host {$cell->getValue()}");
                }
                
                if(is_a($checklists, 'checklist')) {
                    if(!isset($tgt->checklists[$checklists->get_ID()])) {
                        $log->debug("Assigning checklists to {$tgt->get_Name()}", [$checklists]);
                        $tgt->checklists[$checklists->get_ID()] = $checklists;
                    }
                } elseif(is_array($checklists) && count($checklists)) {
                    $log->debug("Assigning checklists to {$tgt->get_Name()}", $checklists);
                    foreach($checklists as $c) {
                        /** @var checklist $c */
                        if(!isset($tgt->checklists[$c->get_ID()])) {
                            $tgt->checklists[$c->get_ID()] = $c;
                        }
                    }
                }
                
                $db->save_Target($tgt);
            }
            else {
                $log->debug("Creating new target {$cell->getValue()}");
                $tgt = new target($cell->getValue());
                $tgt->set_OS_ID((is_a($os, 'software') ? $os->get_ID() : $gen_os->get_ID()));
                $tgt->set_OS_String((is_a($os, 'software') ? $os->get_Shortened_SW_String() : $gen_os->get_Shortened_SW_String()));
                $tgt->set_STE_ID($conf['ste']);
                $tgt->set_Location($conf['location']);
                $tgt->set_Notes('New Target');
                
                if(is_a($checklists, 'checklist')) {
                    if(!isset($tgt->checklists[$checklists->get_ID()])) {
                        $tgt->checklists[$checklists->get_ID()] = $checklists;
                    }
                } elseif(is_array($checklists) && count($checklists)) {
                    foreach($checklists as $c) {
                        /** @var checklist $c */
                        if(!isset($tgt->checklists[$c->get_ID()])) {
                            $tgt->checklists[$c->get_ID()] = $c;
                        }
                    }
                }
                
                if (preg_match('/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}/', $cell->getValue())) {
                    $ip                       = $cell->getValue();
                    $int                      = new interfaces(null, null, null, $ip, null, null, null, null);
                    $tgt->interfaces["{$ip}"] = $int;
                }

                $tgt->set_ID($db->save_Target($tgt));
            }

            $tgts[] = $tgt;

            $log->debug("Adding new target to host list", ['row_count' => $row_count, 'tgt_id' => $tgt->get_ID(), 'tgt_name' => $tgt->get_Name()]);
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

            if(!isset($scan->get_Host_List()[$tgt->get_ID()])) {
                $scan->add_Target_to_Host_List($hl);
            } else {
                $existingFindingCount = $scan->get_Host_List()[$tgt->get_ID()]->getFindingCount();
                $hl->addFindingCount($existingFindingCount);
                $scan->add_Target_to_Host_List($hl);
            }
        }

        $db->update_Scan_Host_List($scan);
        $tgt_findings[$tgt->get_ID()] = $db->get_Finding($tgt);

        if (preg_match('/overall/i', $cell->getValue())) {
            $log->debug("Found overall: {$cell->getColumn()}");
            break;
        }
    }
    
    if(count($tgts) > 100) {
        $db->update_Running_Scan($base_name, ['name' => 'status', 'value' => 'ERROR']);
        $db->update_Running_Scan($base_name, ['name' => 'notes', 'value' => "Too many targets in worksheet {$wksht->getTitle()}"]);
        $log->error("Too many targets in worksheet {$wksht->getTitle()}");
        unset($objSS);
        rename($cmd['f'], TMP . "/terminated/$base_name");
        die();
    }

    $db->update_Running_Scan($base_name, ['name' => 'host_count', 'value' => count($tgts)]);

    // increment the column indexes for notes, check contents, and missing PDI
    if (is_array($tgts) && count($tgts) > 1) {
        $increase = count($tgts) - 1;
        $idx['overall']        += $increase;
        $idx['consistent']     += $increase;
        $idx['notes']          += $increase;
        $idx['check_contents'] += $increase;
    }
    elseif (empty($tgts)) {
		$log->warning("Failed to identify targets in worksheet {$wksht->getTitle()}");
        continue;
    }

    $stig_col  = Coordinate::stringFromColumnIndex($idx['stig_id']);
    $vms_col   = Coordinate::stringFromColumnIndex($idx['vms_id']);
    $cat_col   = Coordinate::stringFromColumnIndex($idx['cat_lvl']);
    $ia_col    = Coordinate::stringFromColumnIndex($idx['ia_controls']);
    $title_col = Coordinate::stringFromColumnIndex($idx['short_title']);
    $notes_col = Coordinate::stringFromColumnIndex($idx['notes']);

    $log->debug("Columns", [
        'stig_col' => $stig_col,
        'vms_col' => $vms_col,
        'cat_col' => $cat_col,
        'ia_col' => $ia_col,
        'title_col' => $title_col,
        'overall_col' => Coordinate::stringFromColumnIndex($idx['overall']),
        'consistent_col' => Coordinate::stringFromColumnIndex($idx['consistent']),
        'check_contents_col' => Coordinate::stringFromColumnIndex($idx['check_contents']),
        'notes_col' => $notes_col
    ]);

    $new_findings     = [];
    $updated_findings = [];
    $row_count = 0;

    foreach ($wksht->getRowIterator(11) as $row) {
        $stig_id     = $wksht->getCell("{$stig_col}{$row->getRowIndex()}")->getValue();
        $cat_lvl     = substr_count($wksht->getCell("{$cat_col}{$row->getRowIndex()}")->getValue(), "I");
        $short_title = $wksht->getCell("{$title_col}{$row->getRowIndex()}")->getValue();
        $notes       = $wksht->getCell("{$notes_col}{$row->getRowIndex()}")->getValue();

        $stig = $db->get_Stig($stig_id);
        if($row->getRowIndex() % 10 == 0) {
            $scan->isTerminated();
        }

        if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
            $stig = $stig[0];
        }
        else {
            $pdi    = new pdi(null, $cat_lvl, $dt->format("Y-m-d"));
            $pdi->set_Short_Title($short_title);
            $pdi->set_Group_Title($short_title);
            if (!($pdi_id = $db->save_PDI($pdi))) {
				die($log->error("Failed to add new PDI for STIG ID {$stig_id}"));
            }

            $stig = new stig($pdi_id, $stig_id, $short_title);
            $db->add_Stig($stig);
        }

        $x = 0;
        foreach ($tgts as $tgt) {
            $status = $wksht->getCell(Coordinate::stringFromColumnIndex($idx['target'] + $x) . $row->getRowIndex())
                ->getValue();

			$findings = $tgt_findings[$tgt->get_ID()];
			if (is_array($findings) && count($findings) && isset($findings[$stig->get_PDI_ID()]) && is_a($findings[$stig->get_PDI_ID()], 'finding')) {
                /** @var finding $tmp */
                $tmp = $findings[$stig->get_PDI_ID()];

                $tmp->set_Finding_Status_By_String($status);
                $tmp->set_Notes($notes);
                $tmp->set_Category($cat_lvl);

                $updated_findings[] = $tmp;
            }
            else {
                $tmp = new finding($tgt->get_ID(), $stig->get_PDI_ID(), $scan->get_ID(), $status, $notes, null, null, null);
                $tmp->set_Category($cat_lvl);

                $new_findings[] = $tmp;
            }
            $log->debug("{$tgt->get_Name()} {$stig->get_ID()} ({$tmp->get_Finding_Status_String()})");
            $x++;
        }         
        
        if(count($updated_findings) + count($new_findings) >= 1000) {
            if(!$db->add_Findings_By_Target($updated_findings, $new_findings)) {
                die(print_r(debug_backtrace(), true));
            } else {
                $updated_findings = [];
                $new_findings = [];
            }
        }

        $db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => (($row->getRowIndex() - 10) / $highestRow) * 100]);
        if (PHP_SAPI == 'cli') {
            print "\r" . sprintf("%.2f%%", (($row->getRowIndex() - 10) / $highestRow) * 100);
        }
    }

    if (!$db->add_Findings_By_Target($updated_findings, $new_findings)) {
        print "Error adding finding" . PHP_EOL;
    }
}

/** @var host_list $h */
foreach($scan->get_Host_List() as $h) {
    $db->update_Target_Counts($h->getTargetId());
}

unset($objSS);
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
