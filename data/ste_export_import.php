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
 *
 *  @TODO - Change to export and import CPE
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$db = new db();

$cmd = getopt("f::", array("import::"));

if (isset($_REQUEST['export'])) {
  if (!isset($_REQUEST['ste'])) {
    print "You must select an ST&amp;E <a href='javascript:void(0);' onclick='javascript:history.go(-1);'>Back</a>";
    exit;
  }

  if ($_REQUEST['export'] == 'Export STE') {
    export_STE();
  }
  elseif ($_REQUEST['export'] == 'Export Host List') {
    export_Host_List();
  }
}
elseif (isset($cmd['import'])) {
  import_STE();
}
else {
  print "Usage: php ste_export_import.php -f=\"{path_to_ste_import_file}\" --import" . PHP_EOL;
}

/**
 * Function to export an ST&amp;E
 */
function export_STE() {
  set_time_limit(0);
  global $db;

  $log = new Sagacity_Error("STE_Export.log");

  $ste = $db->get_STE($_REQUEST['ste'])[0];
  $json = [
    'ste'           => [
      'id'         => $ste->get_ID(),
      'system_id'  => $ste->get_System()->get_ID(),
      'site_id'    => $ste->get_Site()->get_ID(),
      'eval_start' => $ste->get_Eval_Start_Date()->format("Y-m-d"),
      'eval_end'   => $ste->get_Eval_End_Date()->format("Y-m-d")
    ],
    'systems'       => [],
    'site'          => [],
    'ste_cats'      => [],
    'targets'       => [],
    'scans'         => [],
    'tech_findings' => [],
    'proc_findings' => []
  ];

  $system_arr = $db->get_System($ste->get_System()->get_ID());
  foreach ($system_arr as $key => $sys) {
    $json['systems'][] = [
      'id'                => $sys->get_ID(),
      'name'              => $sys->get_Name(),
      'mac'               => $sys->get_MAC(),
      'classification'    => $sys->get_Classification(),
      'abbr'              => $sys->get_Abbreviation(),
      'exec-summary'      => $sys->get_Executive_Summary(),
      'accrediation-type' => $sys->get_Accreditation_Type(),
      'desc'              => $sys->get_Description(),
      'mitigations'       => $sys->get_Mitigations()
    ];
  }

  $json['site'] = [
    'id'      => $ste->get_Site()->get_ID(),
    'name'    => $ste->get_Site()->get_Name(),
    'address' => $ste->get_Site()->get_Address(),
    'city'    => $ste->get_Site()->get_City(),
    'state'   => $ste->get_Site()->get_State(),
    'zip'     => $ste->get_Site()->get_Zip(),
    'country' => $ste->get_Site()->get_Country(),
    'poc'     => $ste->get_Site()->get_POC_Name(),
    'email'   => $ste->get_Site()->get_POC_Email(),
    'phone'   => $ste->get_Site()->get_POC_Phone()
  ];

  $cat_arr = $db->get_STE_Cat_List($ste->get_ID());
  foreach ($cat_arr as $key => $cat) {
    $json['ste_cats'][] = [
      'id'      => $cat->get_ID(),
      'ste_id'  => $cat->get_STE_ID(),
      'name'    => $cat->get_Name(),
      'analyst' => $cat->get_Analyst()
    ];
  }

  $all_findings = [];
  $targets_arr = $db->get_Target_Details($ste->get_ID());
  $used_cats = [];
  if (empty($targets_arr)) {
    $log->script_log("There are no targets in the ST&E", E_ERROR);
  }
  foreach ($targets_arr as $key => $tgt) {
    if (!in_array($tgt->get_Cat_ID(), $used_cats)) {
      $all_findings = array_merge($all_findings, $db->get_Category_Findings($tgt->get_Cat_ID()));
      $used_cats[] = $tgt->get_Cat_ID();
    }
    $os = $db->get_Software($tgt->get_OS_ID())[0];

    $tgt_node = [
      'id'              => $tgt->get_ID(),
      'ste_id'          => $tgt->get_STE_ID(),
      'cat_id'          => $tgt->get_Cat_ID(),
      'os_id'           => $tgt->get_OS_ID(),
      'os_string'       => $tgt->get_OS_String(),
      'os_man'          => $os->get_Man(),
      'os_name'         => $os->get_Name(),
      'os_ver'          => $os->get_Version(),
      'name'            => $tgt->get_Name(),
      'location'        => $tgt->get_Location(),
      'source'          => $tgt->get_Source(),
      'pp_flag'         => '0',
      'pp_off'          => '1',
      'login'           => $tgt->get_Login(),
      'class'           => $tgt->classification,
      'status'          => [
        'auto'    => $tgt->get_Auto_Status_ID(),
        'manual'  => $tgt->get_Man_Status_ID(),
        'data'    => $tgt->get_Data_Status_ID(),
        'fp_cat1' => $tgt->get_FP_Cat1_Status_ID()
      ],
      'notes'           => $tgt->get_Notes(),
      'netstat'         => $tgt->get_Netstat_Connections(),
      'missing_patches' => $tgt->get_Missing_Patches(),
      'interfaces'      => [],
      'software_list'   => [],
      'checklist_list'  => []
    ];

    foreach ($tgt->interfaces as $int) {
      $int_node = [
        'id'        => $int->get_ID(),
        'name'      => $int->get_Name(),
        'ipv4'      => $int->get_IPv4(),
        'ipv6'      => $int->get_IPv6(),
        'hostname'  => $int->get_Hostname(),
        'fqdn'      => $int->get_FQDN(),
        'desc'      => $int->get_Description(),
        'tcp_ports' => [],
        'udp_ports' => []
      ];

      foreach ($int->get_TCP_Ports() as $tcp) {
        $int_node['tcp_ports'][] = [
          'number' => $tcp->get_Port(),
          'name'   => $tcp->get_IANA_Name(),
          'banner' => $tcp->get_Banner(),
          'notes'  => $tcp->get_Notes()
        ];
      }

      foreach ($int->get_UDP_Ports() as $udp) {
        $int_node['udp_ports'][] = [
          'number' => $udp->get_Port(),
          'name'   => $udp->get_IANA_Name(),
          'banner' => $udp->get_Banner(),
          'notes'  => $udp->get_Notes()
        ];
      }

      $tgt_node['interfaces'][] = $int_node;
    }

    foreach ($tgt->software as $sw) {
      $tgt_node['software_list'][] = [
        'id'           => $sw->get_ID(),
        'man'          => $sw->get_Man(),
        'name'         => $sw->get_Name(),
        'ver'          => $sw->get_Version(),
        'string'       => $sw->get_SW_String(),
        'short_string' => $sw->get_Shortened_SW_String()
      ];
    }

    foreach ($tgt->checklists as $chk) {
      $tgt_node['checklist_list'][] = [
        'id'           => $chk->get_ID(),
        'checklist_id' => $chk->get_Checklist_ID(),
        'type'         => $chk->get_type(),
        'class'        => $chk->get_Classification(),
        'version'      => $chk->get_Version(),
        'release'      => $chk->get_Release()
      ];
    }

    $json['targets'][] = $tgt_node;
  }

  if (!is_null($scan_arr = $db->get_ScanData($ste->get_ID()))) {
    foreach ($scan_arr as $scan) {
      $scan_node = [
        'id'        => $scan->get_ID(),
        'ste_id'    => $scan->get_STE()->get_ID(),
        'src_id'    => $scan->get_Source()->get_ID(),
        'itr'       => $scan->get_Itr(),
        'file_name' => $scan->get_File_Name(),
        'file_date' => $scan->get_File_Date(),
        'host_list' => []
      ];

      foreach ($scan->get_Host_List() as $host) {
        $scan_node['host_list'][] = [
          'tgt_id'   => $host['target']->get_ID(),
          'tgt_name' => $host['target']->get_Name(),
          'count'    => $host['count']
        ];
      }

      $json['scans'][] = $scan_node;
    }
  }

  foreach ($all_findings as $worksheet_name => $data) {
    foreach ($data['stigs'] as $stig_id => $data2) {
      $stig = $db->get_Stig($stig_id);
      if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
        $stig = $stig[0];
      }
      else {
        continue;
      }

      $ec = $db->get_eChecklist($stig, $data2['chk_id']);

      $find_node = [
        'stig_id'        => $stig->get_ID(),
        'vms_id'         => $ec->get_VMS_ID(),
        'cat'            => $ec->get_Cat_Level_String(),
        'short_title'    => $ec->get_Short_Title(),
        'check_contents' => $ec->get_Check_Contents(),
        'notes'          => $data2['notes'],
        'target_status'  => [],
        'ia_controls'    => []
      ];

      foreach ($data['target_list'] as $host_name => $col_id) {
        $tgt = $db->get_Target_Details($ste->get_ID(), $host_name)[0];
        $finding = $db->get_Finding($tgt, $stig)[0];

        if (is_null($finding)) {
          continue;
        }

        $find_node['target_status'][] = [
          'tgt_name' => $host_name,
          'status'   => (isset($data2[$host_name]) ? $data2[$host_name] : 'Not Applicable'),
          'scan_id'  => $finding->get_Scan_ID()
        ];
      }

      foreach ($data2['ia_control'] as $ia) {
        $find_node['ia_controls'] = $ia;
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
function export_Host_List() {
  global $db;
  $csv = "Target ID,Name,HostName,IPv4,FQDN,OS" . PHP_EOL;

  $ste = $db->get_STE($_REQUEST['ste'])[0];

  $tgts = $db->get_Target_Details($_REQUEST['ste']);

  foreach ($tgts as $key => $tgt) {
    $csv .= $tgt->get_ID() . "," . $tgt->get_Name() . ",";

    $int_str = '';
    $fqdn_str = '';
    $host_str = '';
    foreach ($tgt->interfaces as $key2 => $int) {
      if (false) {
        $int = new interfaces();
      }
      $host_str .= $int->get_Hostname() . ",";
      $int_str .= $int->get_IPv4() . ",";
      $fqdn_str .= $int->get_FQDN() . ",";
    }
    $host_str = substr($host_str, 0, -1);
    $int_str = substr($int_str, 0, -1);
    $fqdn_str = substr($fqdn_str, 0, -1);

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
function import_STE() {
  global $cmd, $db;
  set_time_limit(0);
  $base_name = basename($cmd['f']);
  include_once 'helper.inc';
  $log = new Sagacity_Error($cmd['f']);

  if (!file_exists($cmd['f'])) {
    $log->script_log("File not found", E_ERROR);
  }

  $xml = new DOMDocument();
  $ste_cat_arr = array();
  $all_scans = array();
  $all_tgts = array();

  if (!$xml->load($cmd['f'])) {
    $log->script_log("Error loading XML", E_ERROR);
  }

  $site_node = getValue($xml, "/root/site", null, true);

  if ($site_node->length) {
    $site_node = $site_node->item(0);
    $site = $db->get_Site($site_node->getAttribute("name"));
    if (is_array($site) && count($site)) {
      $site = $site[0];
      print "Existing site " . $site->get_Name() . PHP_EOL;
    }
    else {
      print "Adding new site " . $site_node->getAttribute("name") . PHP_EOL;
      $site = new site(null, $site_node->getAttribute("name"), $site_node->getAttribute("address"), $site_node->getAttribute("city"), $site_node->getAttribute("state"), $site_node->getAttribute("zip"), $site_node->getAttribute("country"), $site_node->getAttribute("poc_name"), $site_node->getAttribute("poc_email"), $site_node->getAttribute("poc_phone"));

      $site->set_ID($db->save_Site($site));
    }
  }
  else {
    $log->script_log("No site associated with this ST&E", E_ERROR);
  }

  $sys_nodes = getValue($xml, "/root/systems/system", null, true);

  if ($sys_nodes->length) {
    foreach ($sys_nodes as $node) {
      $sys = $db->get_System($node->getAttribute("name"));
      if (is_array($sys) && count($sys)) {
        $sys = $sys[0];
        print "Existing system " . $sys->get_Name() . PHP_EOL;
      }
      else {
        print "Adding new system " . $node->getAttribute("name") . PHP_EOL;
        $sys = new system(null, $node->getAttribute("name"), $node->getAttribute("mac"), $node->getAttribute("classified"));

        $sys->set_ID($db->save_System($sys));
      }
    }
  }
  else {
    $log->script_log("No system associated with this ST&E", E_ERROR);
  }

  $ste_node = getValue($xml, "/root/ste", null, true);

  if ($ste_node->length) {
    print "Adding new ST&E" . PHP_EOL;
    $ste_node = $ste_node->item(0);
    $old_ste_id = $ste_node->getAttribute("id");

    $ste = new ste(null, $sys->get_ID(), $site->get_Id(), $ste_node->getAttribute("eval_start"), $ste_node->getAttribute("eval_end"), false, 0);

    $ste->set_ID($db->save_STE($ste));
  }
  else {
    $log->script_log("No ST&E in this export file", E_ERROR);
  }

  $cat_nodes = getValue($xml, "/root/ste_cats/cat", null, true);

  if ($cat_nodes->length) {
    foreach ($cat_nodes as $node) {
      print "Adding new category " . $node->getAttribute("name") . PHP_EOL;
      $id = $node->getAttribute('id');
      $ste_cat_arr[$id] = new ste_cat(null, $ste->get_ID(), $node->getAttribute("name"), $node->getAttribute("analysts"));

      $ste_cat_arr[$id]->set_ID($db->save_Category($ste_cat_arr[$id]));
    }
  }
  else {
    $log->script_log("There are no categories in this ST&E", E_ERROR);
  }

  $tgt_nodes = getValue($xml, "/root/targets/target", null, true);

  if ($tgt_nodes->length) {
    foreach ($tgt_nodes as $node) {
      print "Adding new target " . $node->getAttribute("name") . PHP_EOL;
      $cat_id = $node->getAttribute("cat_id");

      $os = $db->get_Software([
        'man'  => $node->getAttribute("os_man"),
        'name' => $node->getAttribute("os_name"),
        'ver'  => $node->getAttribute("os_ver")
      ]);

      if (is_array($os) && count($os)) {
        $os = $os[0];
      }
      else {
        $os = $db->getSoftware(array(
              'man'  => 'Generic',
              'name' => 'Generic',
              'ver'  => 'N/A'
                ), false)[0];
      }

      $statuses = getValue($xml, "status", $node, true)->item(0);
      $notes = getValue($xml, "notes", $node);
      $netstat = getValue($xml, "netstat_connection", $node);
      $patches = getValue($xml, "missing_patches", $node);
      $os_string = getValue($xml, "os_string", $node);

      $tgt = new target($node->getAttribute("name"));
      $tgt->set_STE_ID($ste->get_ID());
      $tgt->set_Cat_ID($ste_cat_arr[$cat_id]->get_ID());
      $tgt->set_OS_ID($os->get_ID());
      $tgt->set_OS_String($node->getAttribute("os_string"));
      $tgt->set_Auto_Status_ID($statuses->getAttribute("auto"));
      $tgt->set_Man_Status_ID($statuses->getAttribute("manual"));
      $tgt->set_Data_Status_ID($statuses->getAttribute("data"));
      $tgt->set_FP_Cat1_Status_ID($statuses->getAttribute("fp_cat1"));
      $tgt->set_Location($node->getAttribute("location"));
      $tgt->set_Notes($notes);
      $tgt->set_Netstat_Connections($netstat);
      $tgt->set_Login($node->getAttribute("login"));
      $tgt->set_Missing_Patches($patches);
      $tgt->set_PP_Flag($node->getAttribute("pp_flag"));
      $tgt->set_PP_Suspended($node->getAttribute("pp_off"));

      $ints = getValue($xml, "interfaces/interface", $node, true);
      foreach ($ints as $int_node) {
        $int = new interfaces(null, null, $int_node->getAttribute("name"), $int_node->getAttribute("ipv4"), $int_node->getAttribute("ipv6"), $int_node->getAttribute("hostname"), $int_node->getAttribute("fqdn"), getValue($xml, "description", $int_node));

        $tcp_nodes = getValues($xml, "tcp_ports/port", $int_node, true);
        foreach ($tcp_nodes as $tcp) {
          $int->add_TCP_Ports(new tcp_ports(null, $tcp->getAttribute("number"), $tcp->getAttribute("name"), getValue($xml, "banner", $tcp), getValue($xml, "notes", $tcp)));
        }

        $udp_nodes = getValues($xml, "udp_ports/port", $int_node, true);
        foreach ($udp_nodes as $udp) {
          $int->add_UDP_Ports(new udp_ports(null, $udp->getAttribute("number"), $udp->getAttribute("name"), getValue($xml, "banner", $udp), getValue($xml, "notes", $udp)));
        }

        $tgt->interfaces[] = $int;
      }

      $sw_nodes = getValue($xml, "software_list/software", $node, true);
      foreach ($sw_nodes as $sw) {
        $tgt->software[] = $db->get_Software(array(
              'man'  => $sw->getAttribute("sw_man"),
              'name' => $sw->getAttribute("sw_name"),
              'ver'  => $sw->getAttribute("sw_ver")
            ))[0];
      }

      $chk_nodes = getValue($xml, "checklist_list/checklist", $node, true);
      foreach ($chk_nodes as $chk) {
        $tgt->checklists[] = $db->get_Checklist(array(
              'checklist_id' => $chk->getAttribute('checklist_id'),
              'type'         => $chk->getAttribute('type'),
              'version'      => $chk->getAttribute('version'),
              'release'      => $chk->getAttribute('release')
            ))[0];
      }

      $tgt->set_ID($db->save_Target($tgt));
      $all_tgts[$node->getAttribute("id")] = $tgt;
    }
  }
  else {
    $log->script_log("No targets were found on this ST&E", E_ERROR);
  }

  $scan_nodes = getValue($xml, "/root/scans/scan", null, true);
  if ($scan_nodes->length) {
    foreach ($scan_nodes as $node) {
      $src = $db->get_Sources($node->getAttribute("src_id"));
      print "Adding new scan result file " . $node->getAttribute("file_name") . PHP_EOL;
      $scan = new scan(null, $src, $ste, $node->getAttribute('itr'), $node->getAttribute("file_name"), $node->getAttribute('file_date'));

      $host_list_nodes = getValue($xml, "host_list", $node, true);
      foreach ($host_list_nodes as $host) {
        $scan_tgt = $db->get_Target_Details($ste->get_ID(), $host->getAttribute('tgt_name'))[0];
        $hl = new host_list();
        $hl->setTargetId($scan_tgt->get_ID());
        $hl->setTargetName($scan_tgt->get_Name());
        $hl->setFindingCount($host->getAttribute("count"));
        $hl->setScanError(false);

        $scan->add_Target_to_Host_List($hl);
      }

      $scan->set_ID($db->save_Scan($scan));
      $all_scans[$node->getAttribute("id")] = $scan;
    }
  }
  else {
    $log->script_log("No scan result files were found in this ST&E", E_ERROR);
  }

  $x = 1;
  $finding_nodes = getValue($xml, "/root/tech_findings/finding", null, true);
  if ($finding_nodes->length) {
    print "Adding findings (total " . $finding_nodes->length . ")" . PHP_EOL;
    foreach ($finding_nodes as $node) {
      print ".";
      if ($x % 100 == 0) {
        print "\t$x" . PHP_EOL;
      }

      $ia_nodes = getValue($xml, "ia_control", $node, true);
      $ia_arr = array();
      foreach ($ia_nodes as $ia) {
        $ia_arr[] = $ia->textContent;
      }

      $cc = getValue($xml, "check_contents", $node);

      $tgt_status_nodes = getValue($xml, "target_status", $node, true);
      foreach ($tgt_status_nodes as $status_node) {
        $notes = getValue($xml, "notes", $status_node);
        $tgt = $db->get_Target_Details($ste->get_ID(), $status_node->getAttribute("tgt_name"))[0];
        $finding = array(
          0 => $node->getAttribute("stig_id"),
          1 => $node->getAttribute("vms_id"),
          2 => $node->getAttribute("cat"),
          3 => implode(' ', $ia_arr),
          4 => $node->getAttribute("short_title"),
          5 => $status_node->getAttribute("status"),
          6 => $notes,
          7 => $cc,
          8 => ''
        );

        $db->add_Finding($all_scans[$status_node->getAttribute("scan_id")], $tgt, $finding);
      }
      $x++;
    }
  }
  else {
    $log->script_log("No findings were recorded in this ST&E", E_WARNING);
  }
}
