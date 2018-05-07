<?php
/**
 * File: parse_stig_viewer.php
 * Author: Ryan Prather
 * Purpose: Read STIG Viewer checklist files
 * Created: Apr 10, 2014
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
 *  - Apr 10, 2014 - File created
 *  - Jun 3, 2015 - Copyright updated, added CWD parameter, and
 * 					updated function calls after class merger
 *  - Mar 4, 2017 - Removed Thread class calls
 *  - May 22, 2017 - Migrated to use parse_config.ini file and bug fixed to get working.  Added CLI progress report
 *  - Jun 3, 2017 - Fixed bug #237
 */
$cmd = getopt("f:", ['debug::', 'help::']);

if (!isset($cmd['f']) || isset($cmd['help'])) {
    die(usage());
}

if (!file_exists("parse_config.ini")) {
    die("You must create parse_config.ini file with required parameters");
}

$conf = parse_ini_file("parse_config.ini");

if (!$conf) {
    die("Could not find parse_config.ini configuration file");
}

chdir($conf['doc_root']);

include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

check_path(TMP . "/stig_viewer");
chdir(TMP);

$db        = new db();
$base_name = basename($cmd['f']);
$host_list = [];
$err       = new Sagacity_Error($cmd['f']);

if (!file_exists($cmd['f'])) {
    $db->update_Running_Scan($base_name, ['name' => 'status', 'value' => 'ERROR']);
    $err->script_log("File not found", E_ERROR);
}

$db->update_Running_Scan($base_name, ['name' => 'pid', 'value' => getmypid()]);

$xml = new DOMDocument();
$xml->load($cmd['f']);

$root         = $xml->getElementsByTagName('CHECKLIST')->item(0);
$xmlns        = $xml->createAttribute('xmlns');
$xmlns->value = "http://www.w3.org/2001/XMLSchema-instance";

$root->appendChild($xmlns);

$host_name = getValue($xml, '//HOST_NAME');
$host_ip   = getValue($xml, '//HOST_IP');
$host_mac  = getValue($xml, '//HOST_MAC');

if (!$host_name) {
    $db->update_Running_Scan($base_name, ['name' => 'status', 'value' => 'TERMINATED']);
    unset($xml);

    rename($cmd['f'], TMP . "/terminated/{$base_name}");
    $err->script_log("File parsing terminated because host name was absent", E_ERROR);
    die;
}

if ($tgt_id = $db->check_Target($conf['ste'], $host_name)) {
    $tgt = $db->get_Target_Details($conf['ste'], $tgt_id)[0];
}
elseif ($tgt_id = $db->check_Target($conf['ste'], $host_ip)) {
    $tgt = $db->get_Target_Details($conf['ste'], $tgt_id)[0];
}
else {
    $tgt = new target($host_name);
    $tgt->set_STE_ID($conf['ste']);

    $sw = $db->get_Software("cpe:/o:generic:generic");
    if (is_array($sw) && count($sw) && isset($sw[0]) && is_a($sw[0], 'software')) {
        $sw = $sw[0];

        $tgt->set_OS_ID($sw->get_ID());
        $tgt->set_OS_String($sw->get_Shortened_SW_String());
    }

    $tgt_id = $db->save_Target($tgt);
    $tgt->set_ID($tgt_id);
}

$source = $db->get_Sources('STIG Viewer');
if (is_array($source) && count($source) && isset($source[0]) && is_a($source[0], 'source')) {
    $source = $source[0];
}
else {
    die("Could not find source 'STIG Viewer' in DB");
}
$scan = $db->get_ScanData($conf['ste'], $base_name);

$vulns = getValue($xml, '//VULN', null, true);

if (!count($scan)) {
    $fmt     = filemtime($cmd['f']);
    $fdt     = DateTime::createFromFormat('U', $fmt);
    $ste     = $db->get_STE($conf['ste'])[0];
    $scan    = new scan(null, $source, $ste, 1, $base_name, $fdt->format('Y-m-d H:i:s'));

    $hl = new host_list();
    $hl->setTargetId($tgt->get_ID());
    $hl->setTargetName($tgt->get_Name());
    $hl->setFindingCount($vulns->length);

    $scan->add_Target_to_Host_List($hl);
    $scan_id = $db->save_Scan($scan);
    $scan->set_ID($scan_id);
}
else {
    $scan = $scan[0];

    $hl = new host_list();
    $hl->setTargetId($tgt->get_ID());
    $hl->setTargetName($tgt->get_Name());
    $hl->setFindingCount($vulns->length);

    $scan->add_Target_to_Host_List($hl);
    $db->update_Scan_Host_List($scan);
}

$vuln_count = 1;

foreach ($vulns as $vul) {
    $stig_data = getValue($xml, "STIG_DATA", $vul, true);

    $arr = [];

    foreach ($stig_data as $node) {
        $db->help->select("sagacity.scans", ['status'], [
            [
                'field' => 'id',
                'op'    => '=',
                'value' => $scan->get_ID()
            ]
        ]);
        $thread_status = $db->help->execute();
        if ($thread_status == 'TERMINATED') {
            unset($xml);
            $source = strtolower($scan->get_Source()->get_Name());
            rename(realpath(TMP . "/{$scan->get_File_Name()}"), realpath(TMP . "/scc/{$scan->get_File_Name()}"));
            $err->script_log("File parsing terminated by user");
            die();
        }

        $attr = getValue($xml, "VULN_ATTRIBUTE", $node);
        $data = getValue($xml, "ATTRIBUTE_DATA", $node);

        switch ($attr) {
            case 'Vuln_Num':
                $arr['vms_id'] = $data;
                break;
            case 'Severity':
                if ($data == 'high') {
                    $arr['cat'] = 1;
                }
                elseif ($data == 'medium') {
                    $arr['cat'] = 2;
                }
                elseif ($data == 'low') {
                    $arr['cat'] = 3;
                }
                else {
                    $arr['cat'] = 2;
                }
                break;
            case 'Rule_ID':
                $arr['sv_rule']       = explode(' ', $data);
                break;
            case 'Rule_Ver':
                $arr['stig_id']       = $data;
                break;
            case 'IA_Controls':
                $arr['ia_controls']   = explode(", ", $data);
                break;
            case 'Check_Content_Ref':
                $arr['ref']           = substr($data, 0, strpos($data, ' :: '));
                break;
            case 'Rule_Title':
                $arr['short_title']   = $data;
                break;
            case 'Vuln_Discuss':
                $arr['desc']          = $data;
                break;
            case 'Check_Content':
                $arr['check_content'] = $data;
                break;
        }
    }

    if (isset($arr['stig_id'])) {
        $stig = $db->get_Stig($arr['stig_id']);
        if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
            $stig = $stig[0];
        }
        else {
            $pdi    = new pdi(null, $arr['cat'], null, $arr['short_title'], $arr['desc']);
            $pdi->set_Short_Title($arr['short_title']);
            $pdi->set_Group_Title($arr['short_title']);
            $pdi->set_Description($arr['desc']);
            $pdi_id = $db->save_PDI($pdi);

            $stig = new stig($pdi_id, $arr['stig_id'], $arr['desc']);
            $db->add_Stig($stig);
            // add stig
        }
    }
    else {
        print_r($arr);
    }

    $status = getValue($xml, 'STATUS', $vul);
    switch ($status) {
        case "Not_Reviewed":
            $status = "Not Reviewed";
            break;
        case "NotAFinding":
            $status = "Not a Finding";
            break;
        case "Not_Applicable":
            $status = "Not Applicable";
    }

    $comments = "(STIG Viewer) " . getValue($xml, 'COMMENTS', $vul);
    $vms      = $db->get_GoldDisk($arr['vms_id']);

    if (empty($vms)) {
        $db->save_GoldDisk(new golddisk($stig->get_PDI_ID(), $arr['vms_id'], $arr['short_title']));
    }

    foreach ($arr['sv_rule'] as $key => $sv_rule) {
        $sv = $db->get_SV_Rule($stig->get_PDI_ID(), $sv_rule);
        if (!count($sv)) {
            $db->save_SV_Rule(array(0 => new sv_rule($stig->get_PDI_ID(), $sv_rule)));
        }
    }

    if (!$oval = $db->get_Oval($arr['ref']) || $oval->get_PDI_ID() != $stig->get_PDI_ID()) {
        $db->add_Oval($oval = new oval($stig->get_PDI_ID(), $arr['ref'], $arr['short_title'], $arr['desc'], null, null, null));
    }

    $tmp = [];

    foreach ($arr['ia_controls'] as $ia) {
        if ($ia) {
            $tmp[] = new ia_control($stig->get_PDI_ID(), substr($ia, 0, 4), substr($ia, 5));
        }
    }

    if (count($tmp)) {
        $db->save_IA_Control($tmp);
    }

    if (!$db->add_Finding($scan, $tgt, [
            $arr['stig_id'],
            $arr['vms_id'],
            implode("", array_fill(0, $arr['cat'], 'I')),
            implode(" ", $arr['ia_controls']),
            $arr['short_title'],
            $status,
            $comments,
            $arr['check_content'],
            ''
            ]
        )) {

    }

    if (php_sapi_name() == 'cli') {
        print "\r" . sprintf("%.02f%%", ($vuln_count / $vulns->length) * 100);
    }

    $db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => ($vuln_count / $vulns->length) * 100]);
    $vuln_count++;
}

unset($xml);
if (!isset($cmd['debug'])) {
    rename($cmd['f'], TMP . "/stig_viewer/$base_name");
}
$db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => 100, 'complete' => 1]);

function usage()
{
    print <<<EOO
Purpose: To parse a STIG Viewer output result file

Usage: php parse_stig_viewer.php -f={STIG Viewer file} [--debug] [--help]

 -f={STIG Viewer file}    The STIG Viewer result file that is being imported

 --debug                  Debugging output
 --help                   This screen

EOO;
}
