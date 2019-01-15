<?php

/**
 * File: ste_export_import.php
 * Author: Ryan Prather
 * Purpose: Export ST&E data
 * Created: Feb 11, 2014
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Feb 11, 2014 - File created
 *  - Sep 1, 2016 - Updated copyright and update scan constructor to use source object instead of source ID
 *  - Nov 7, 2016 - Fix bug with reading source ID
 *  - Apr 5, 2017 - Formatting
 *  - Dec 19, 2017 - Converted from XML to JSON format export/import
 *  - Jan 16, 2018 - Updated to use host_list class
 *  - Nov 19, 2018 - Fixed bug from changes to get_Category_Findings method
 *
 *  @TODO - Change to export and import CPE
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$db = new db();

$cmd = getopt("f::", [
    "import::",
    "export::"
]);

if (isset($_REQUEST['export'])) {
    if (! isset($_REQUEST['ste'])) {
        print "You must select an ST&amp;E <a href='javascript:void(0);' onclick='javascript:history.go(-1);'>Back</a>";
        exit();
    }

    if ($_REQUEST['export'] == 'Export STE') {
        export_STE();
    } elseif ($_REQUEST['export'] == 'Export Host List') {
        export_Host_List();
    }
} elseif (isset($cmd['import'])) {
    import_STE();
} else {
    print "Usage: php ste_export_import.php -f=\"{path_to_ste_import_file}\" --import" . PHP_EOL;
}

/**
 * Function to export an ST&amp;E
 */
function export_STE()
{
    set_time_limit(0);
    global $db;

    $log = new Sagacity_Error("STE_Export.log");

    $ste = $db->get_STE($_REQUEST['ste'])[0];
    $json = [
        'ste' => [
            'id' => $ste->get_ID(),
            'system_id' => $ste->get_System()->get_ID(),
            'site_id' => $ste->get_Site()->get_ID(),
            'eval_start' => $ste->get_Eval_Start_Date()->format("Y-m-d"),
            'eval_end' => $ste->get_Eval_End_Date()->format("Y-m-d")
        ],
        'systems' => [],
        'site' => [],
        'ste_cats' => [],
        'targets' => [],
        'scans' => [],
        'tech_findings' => [],
        'proc_findings' => []
    ];

    $system_arr = $db->get_System($ste->get_System()
        ->get_ID());
    foreach ($system_arr as $sys) {
        $json['systems'][] = [
            'id' => $sys->get_ID(),
            'name' => $sys->get_Name(),
            'mac' => $sys->get_MAC(),
            'classification' => $sys->get_Classification(),
            'abbr' => $sys->get_Abbreviation(),
            'exec-summary' => $sys->get_Executive_Summary(),
            'accrediation-type' => $sys->get_Accreditation_Type(),
            'desc' => $sys->get_Description(),
            'mitigations' => $sys->get_Mitigations()
        ];
    }

    $json['site'] = [
        'id' => $ste->get_Site()->get_ID(),
        'name' => $ste->get_Site()->get_Name(),
        'address' => $ste->get_Site()->get_Address(),
        'city' => $ste->get_Site()->get_City(),
        'state' => $ste->get_Site()->get_State(),
        'zip' => $ste->get_Site()->get_Zip(),
        'country' => $ste->get_Site()->get_Country(),
        'poc' => $ste->get_Site()->get_POC_Name(),
        'email' => $ste->get_Site()->get_POC_Email(),
        'phone' => $ste->get_Site()->get_POC_Phone()
    ];

    $cat_arr = $db->get_STE_Cat_List($ste->get_ID());
    foreach ($cat_arr as $cat) {
        $json['ste_cats'][] = [
            'id' => $cat->get_ID(),
            'ste_id' => $cat->get_STE_ID(),
            'name' => $cat->get_Name(),
            'analyst' => $cat->get_Analyst()
        ];
    }

    $all_findings = [];
    $targets_arr = $db->get_Target_Details($ste->get_ID());
    $used_cats = [];
    if (empty($targets_arr)) {
        $log->script_log("There are no targets in the ST&E", E_ERROR);
    }
    foreach ($targets_arr as $tgt) {
        if (! in_array($tgt->get_Cat_ID(), $used_cats)) {
            $all_findings = array_merge($all_findings, $db->get_Category_Findings($tgt->get_Cat_ID()));
            $used_cats[] = $tgt->get_Cat_ID();
        }
        $os = $db->get_Software($tgt->get_OS_ID())[0];

        $tgt_node = [
            'id' => $tgt->get_ID(),
            'ste_id' => $tgt->get_STE_ID(),
            'cat_id' => $tgt->get_Cat_ID(),
            'os_id' => $tgt->get_OS_ID(),
            'os_string' => $tgt->get_OS_String(),
            'os_man' => $os->get_Man(),
            'os_name' => $os->get_Name(),
            'os_ver' => $os->get_Version(),
            'name' => $tgt->get_Name(),
            'location' => $tgt->get_Location(),
            'source' => $tgt->get_Source(),
            'pp_flag' => '0',
            'pp_off' => '1',
            'login' => $tgt->get_Login(),
            'class' => $tgt->classification,
            'status' => [
                'auto' => $tgt->get_Auto_Status_ID(),
                'manual' => $tgt->get_Man_Status_ID(),
                'data' => $tgt->get_Data_Status_ID(),
                'fp_cat1' => $tgt->get_FP_Cat1_Status_ID()
            ],
            'notes' => $tgt->get_Notes(),
            'netstat' => $tgt->get_Netstat_Connections(),
            'missing_patches' => $tgt->get_Missing_Patches(),
            'interfaces' => [],
            'software_list' => [],
            'checklist_list' => []
        ];

        foreach ($tgt->interfaces as $int) {
            $int_node = [
                'id' => $int->get_ID(),
                'name' => $int->get_Name(),
                'ipv4' => $int->get_IPv4(),
                'ipv6' => $int->get_IPv6(),
                'hostname' => $int->get_Hostname(),
                'fqdn' => $int->get_FQDN(),
                'desc' => $int->get_Description(),
                'tcp_ports' => [],
                'udp_ports' => []
            ];

            foreach ($int->get_TCP_Ports() as $tcp) {
                $int_node['tcp_ports'][] = [
                    'number' => $tcp->get_Port(),
                    'name' => $tcp->get_IANA_Name(),
                    'banner' => $tcp->get_Banner(),
                    'notes' => $tcp->get_Notes()
                ];
            }

            foreach ($int->get_UDP_Ports() as $udp) {
                $int_node['udp_ports'][] = [
                    'number' => $udp->get_Port(),
                    'name' => $udp->get_IANA_Name(),
                    'banner' => $udp->get_Banner(),
                    'notes' => $udp->get_Notes()
                ];
            }

            $tgt_node['interfaces'][] = $int_node;
        }

        foreach ($tgt->software as $sw) {
            $tgt_node['software_list'][] = [
                'id' => $sw->get_ID(),
                'man' => $sw->get_Man(),
                'name' => $sw->get_Name(),
                'ver' => $sw->get_Version(),
                'string' => $sw->get_SW_String(),
                'short_string' => $sw->get_Shortened_SW_String()
            ];
        }

        foreach ($tgt->checklists as $chk) {
            $tgt_node['checklist_list'][] = [
                'id' => $chk->get_ID(),
                'checklist_id' => $chk->get_Checklist_ID(),
                'type' => $chk->get_type(),
                'class' => $chk->get_Classification(),
                'version' => $chk->get_Version(),
                'release' => $chk->get_Release()
            ];
        }

        $json['targets'][] = $tgt_node;
    }

    if (! is_null($scan_arr = $db->get_ScanData($ste->get_ID()))) {
        foreach ($scan_arr as $scan) {
            $scan_node = [
                'id' => $scan->get_ID(),
                'ste_id' => $scan->get_STE()->get_ID(),
                'src_id' => $scan->get_Source()->get_ID(),
                'itr' => $scan->get_Itr(),
                'file_name' => $scan->get_File_Name(),
                'file_date' => $scan->get_File_Date(),
                'host_list' => []
            ];

            foreach ($scan->get_Host_List() as $host) {
                /** @var host_list $host */
                $scan_node['host_list'][] = [
                    'tgt_id' => $host->getTargetId(),
                    'tgt_name' => $host->getTargetName(),
                    'count' => $host->getFindingCount()
                ];
            }

            $json['scans'][] = $scan_node;
        }
    }

    foreach ($all_findings as $data) {
        foreach ($data['stigs'] as $stig_id => $data2) {
            $stig = $db->get_Stig($stig_id);
            if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
                $stig = $stig[0];
            } else {
                continue;
            }

            $ec = $db->get_eChecklist($stig, $data2['chk_id']);

            $find_node = [
                'stig_id' => $stig->get_ID(),
                'vms_id' => $ec->get_VMS_ID(),
                'cat' => $ec->get_Cat_Level(),
                'short_title' => $ec->get_Short_Title(),
                'check_contents' => $ec->get_Check_Contents(),
                'notes' => trim($data2['echecklist']->get_Notes()),
                'target_status' => [],
                'ia_controls' => $data2['echecklist']->get_IA_Controls()
            ];
            
            unset($data['stigs'][$stig_id]['echecklist']);
            unset($data['stigs'][$stig_id]['chk_id']);

            foreach ($data['stigs'][$stig_id] as $host_name => $status) {
                $find_node['target_status'][] = [
                    'tgt_name' => $host_name,
                    'status' => $status,
                    //'scan_id' => $finding->get_Scan_ID()
                ];
            }
            
            $json['tech_findings'][] = $find_node;
        }
    }

    header(JSON);
    header('Content-disposition: attachment; filename="' . $sys->get_Name() . '-' . $ste->get_Site()->get_Name() . '-ste-export.json"');
    print json_encode($json, JSON_PRETTY_PRINT);
}

/**
 * Function to export the hosts in an ST&amp;E
 */
function export_Host_List()
{
    global $db;
    $csv = "Target ID,Name,HostName,IPv4,FQDN,OS" . PHP_EOL;

    $ste = $db->get_STE($_REQUEST['ste'])[0];

    $tgts = $db->get_Target_Details($_REQUEST['ste']);

    foreach ($tgts as $tgt) {
        $csv .= $tgt->get_ID() . "," . $tgt->get_Name() . ",";

        $int_str = '';
        $fqdn_str = '';
        $host_str = '';
        foreach ($tgt->interfaces as $int) {
            /** @var interfaces $int */
            $host_str .= $int->get_Hostname() . ",";
            $int_str .= $int->get_IPv4() . ",";
            $fqdn_str .= $int->get_FQDN() . ",";
        }
        $host_str = substr($host_str, 0, - 1);
        $int_str = substr($int_str, 0, - 1);
        $fqdn_str = substr($fqdn_str, 0, - 1);

        $csv .= "\"$host_str\",\"$int_str\",\"$fqdn_str\",";

        $os = $db->get_Software($tgt->get_OS_ID())[0];
        $csv .= $os->get_Man() . " " . $os->get_Name() . " " . $os->get_Version() . PHP_EOL;
    }

    header('Content-type: plain/text');
    header('Content-disposition: attachment; filename="' . $ste->get_System()->get_Name() . '-' . $ste->get_Site()->get_Name() . '-host-list.csv"');
    print $csv;
}

/**
 * Function to import an ST&amp;E
 */
function import_STE()
{
}
