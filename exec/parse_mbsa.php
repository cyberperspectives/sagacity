<?php

/**
 * File: parse_mbsa.php
 * Author: Ryan Prather
 * Purpose: Background script to parse MBSA files
 * Created: July 3, 2014
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
 *  - July 3, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter, and updated functions after class merger
 *  - Mar 4, 2017 - Removed Thread class calls
 *  - Jun 3, 2017 - Changed to check thread status and die if changed to TERMINATED
 */
$cmd = getopt("f:s:d:", array('debug::', 'help::'));

if (!isset($cmd['f']) || !isset($cmd['s']) || isset($cmd['help'])) {
  usage();
  exit;
}

include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

check_path(TMP . "/mbsa");
chdir(TMP);

set_time_limit(0);

$err = new Sagacity_Error($cmd['f']);

if (!file_exists($cmd['f'])) {
  $db->update_Running_Scan(basename($cmd['f']), array('name' => 'status', 'value' => 'ERROR'));
  $err->script_log("File not found", E_ERROR);
}

$db = new db();
$base_name = basename($cmd['f']);
$host_list = array();

$db->update_Running_Scan($base_name, array('name' => 'pid', 'value' => getmypid()));

$src = $db->get_Sources("MBSA");

$existing_scan = $db->get_ScanData($cmd['s'], $base_name);

if (is_array($existing_scan) && count($existing_scan)) {
  $scan = $existing_scan[0];
}
else {
  $dt = new DateTime();
  $ste = $db->get_STE($cmd['s'])[0];
  $scan = new scan(null, $src, $ste, 0, $base_name, $dt->format("Y-m-d"));
  $scan_id = $db->save_Scan($scan);

  $scan->set_ID($scan_id);
}

if (substr($base_name, -3) == 'xml') {
  $match = array();
  if (preg_match('/([^\\\\]+)\-mbsa\.xml/i', $cmd['f'], $match)) {
    $tgt_id = get_a_tgt_id($db, $cmd['s'], $match[1], $match[1]);
    $tgt = $db->get_Target_Details($cmd['s'], $tgt_id)[0];
  }
  else {
    $err->script_log("File name is not the correct format (hostname)-mbsa.xml required! (" . $base_name . ")", E_ERROR);
  }

  $host_list = array(
    'target' => $tgt,
    'count'  => 0
  );

  $xml = new DOMDocument();
  $xml->load($cmd['f']);

  $checks = getValue($xml, "/x:XMLOut/x:Check/x:Detail/x:UpdateData", null, true);
  foreach ($checks as $check) {
    $db->help->select("sagacity.scans", array('status'), array(
      array(
        'field' => 'id',
        'op'    => '=',
        'value' => $scan->get_ID()
      )
    ));
    $thread_status = $db->help->execute();
    if ($thread_status['status'] == 'TERMINATED') {
      unset($xml);
      rename(realpath(TMP . "/{$scan->get_File_Name()}"), TMP . "/terminated/{$scan->get_File_Name()}");
      $err->script_log("File parsing terminated by user");
      die();
    }

    $ms = getValue($xml, "@BulletinID", $check);
    $kb = getValue($xml, "@KBID", $check) ? "KB" . getValue($xml, "@KBID", $check) : "";
    $installed = (getValue($xml, "@IsInstalled", $check) == 'true' ? true : false);

    if ($ms) {
      $adv = $db->get_Advisory($ms);
      $iavm = $db->get_IAVM_From_External($ms);

      if (is_null($iavm) && $kb) {
        $iavm = $db->get_IAVM_From_External($kb);
      }
    }
    elseif ($kb) {
      $adv = $db->get_Advisory($kb);
      $iavm = $db->get_IAVM_From_External($kb);
    }
    else {
      $adv = null;
      $iavm = null;
    }

    $err->script_log("$ms/$kb");

    if (is_array($adv) && count($adv)) {
      $adv = $adv[0];
    }

    if ($iavm && $iavm->get_PDI_ID()) {
      $status = 'Open';
      if ($installed) {
        $status = 'Not a Finding';
      }

      $stig = $db->get_Stig($iavm->get_Notice_Number());
      if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
        $stig = $stig[0];
      }

      $err->script_log("pdi\t=\t" . $stig->get_PDI_ID() . "\tstig\t=\t" . $stig->get_ID());

      $pdi = $db->get_PDI($stig->get_PDI_ID());
      $vms = $db->get_GoldDisk_By_PDI($pdi->get_ID());
      $ias = $db->get_IA_Controls_By_PDI($pdi->get_ID());

      if (is_array($vms) && count($vms) && isset($vms[0]) && is_a($vms[0], 'stig')) {
        $vms = $vms[0];
      }
      else {
        $vms = '';
      }

      $finding = $db->get_Finding($tgt, $iavm, $scan);

      if (!count($finding)) {
        $ia_str = '';
        foreach ($ias as $key => $ia):$ia_str .= $ia->get_Type() . "-" . $ia->get_Type_ID() . " ";
        endforeach;

        $finding = array(
          0 => $stig->get_ID(),
          1 => (is_a($vms, 'golddisk') ? $vms->get_ID() : $vms),
          2 => $pdi->get_Category_Level_String(),
          3 => $ia_str,
          4 => $pdi->get_Short_Title(),
          5 => $status,
          6 => '(MBSA)',
          7 => $pdi->get_Check_Contents(),
          8 => ''
        );

        $host_list['count'] ++;

        if (!$db->add_Finding($scan, $tgt, $finding)) {
          $err->script_log("add finding failure");
        }/**/
      }
      else {
        // need to code update for MBSA
      }
    }
    else {
      $err->script_log("don't have iavm");
      $cves = getValue($xml, "x:OtherIDs/x:OtherID[@Type='CVE']", $check, true);

      if ($cves->length) {
        foreach ($cves as $cve) {
          $db_cve = $db->get_CVE($cve->textContent);

          if ($db_cve) {
            if (count($db_cve->get_IAVM())) {
              $iavm = $db->get_IAVM($db_cve->get_IAVM()[0]);
            }
            break;
          }
        }

        if ($iavm && $iavm->get_PDI_ID()) {
          $err->script_log("found one");
          $status = 'Open';
          if ($installed) {
            $status = 'Not a Finding';
          }

          $pdi = $db->get_PDI($iavm->get_PDI_ID());
          $vms = $db->get_GoldDisk_By_PDI($pdi->get_ID());
          $ias = $db->get_IA_Controls_By_PDI($pdi->get_ID());

          if (is_array($vms) && count($vms)) {
            $vms = $vms[0];
          }
          else {
            $vms = '';
          }

          $finding = $db->get_Finding($tgt, $iavm, $scan);

          if (!count($finding)) {
            $ia_str = '';
            foreach ($ias as $key => $ia):$ia_str .= $ia->get_Type() . "-" . $ia->get_Type_ID() . " ";
            endforeach;

            $finding = array(
              0 => $iavm->get_Notice_Number(),
              1 => (is_a($vms, 'golddisk') ? $vms->get_ID() : $vms),
              2 => $pdi->get_Category_Level_String(),
              3 => $ia_str,
              4 => $pdi->get_Short_Title(),
              5 => $status,
              6 => '',
              7 => $pdi->get_Check_Contents(),
              8 => ''
            );

            $host_list['count'] ++;

            if (!$db->add_Finding($scan, $tgt, $finding)) {
              $err->script_log("add finding failure");
            }/**/
          }
          else {

          }
        }
      }
      else {
        $cve = $db->get_CVE_From_External(substr($kb, 2));
        if ($cve && $cve->get_PDI_ID()) {
          $err->script_log("found one");
          $err->script_log("pdi: " . $cve->get_PDI_ID());
        }
        else {
          $err->script_log("still don't have it");
        }
      }
    }
  }
}
elseif (substr($base_name, -3) == 'txt') {

}

$db->update_Scan_Host_List($scan, array(0 => $host_list));
if (!isset($cmd['debug'])) {
  rename($cmd['f'], DOC_ROOT . "/tmp/mbsa/$base_name");
}
$db->update_Running_Scan($base_name, array('name' => 'perc_comp', 'value' => 100, 'complete' => 1));

function usage() {
  print <<<EOO
Purpose: To import an MBSA result file

Usage: php parse_mbsa.php -s={ST&E ID} -f={result file} [--debug] [--help]

 -s={ST&E ID}       The ST&E ID this result file is being imported for
 -f={result file}   The result file to import

 --debug            Debugging output
 --help             This screen

EOO;
}
