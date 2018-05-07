<?php

/**
 * File: parse_ms_kb_to_cve.php
 * Author: Ryan Prather
 * Purpose: To parse Excel MS/KB to CVE file retrieved from https://technet.microsoft.com/en-us/security/bulletin
 *    Released on the second Tues of the month
 * Created: Jul 9, 2014
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
 *  - Jul 9, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated and updated functions after class merger
 */
$cmd = getopt("f:", array('debug::'));
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

chdir(DOC_ROOT . "/tmp");

set_time_limit(0);

$db = new db();
$base_name = basename($cmd['f']);
$err = new Sagacity_Error($cmd['f']);

if (!file_exists($cmd['f'])) {
  $db->update_Running_Scan($base_name, array('name' => 'status', 'value' => 'ERROR'));
  $err->script_log("File not found", E_ERROR);
}

$start = new DateTime();

$fh = fopen($cmd['f'], "r");
$row = fegetcsv($fh);
while ($row = fgetcsv($fh)) {
  print ".";
  $adv = array();
  $ms_url = '';
  $kb_url = '';
  $sev = 'II';
  $pdi_id = 0;
  $date = $row[0];
  $ms = $row[1];

  switch ($row[3]) {
    case 'Critical':
    case 'Important':
      $sev = 'I';
      break;
    case 'Low':
      $sev = 'III';
      break;
  }

  $impact = $row[4];
  $title = $row[5];
  $prod = $row[6];
  $kb = "KB" . (isset($row[7]) && !empty($row[7]) ? $row[7] : $row[2]);
  $comp = $row[8];
  $cves = explode(",", $row[13]);

  if (isset($cmd['debug'])) {
    $err->script_log("$ms/$kb/$date");
  }

  $db_cve = null;
  $has_cve = false;

  if (is_array($cves) && count($cves)) {
    foreach ($cves as $cve) {
      $db_cve = $db->get_CVE($cve);

      if (!is_null($db_cve)) {
        if ($db_cve->get_PDI_ID()) {
          $has_cve = true;
        }

        $dt = DateTime::createFromFormat("m-d-y", $date);
        $db_cve->set_Phase_Date($dt->format("Y-m-d"));

        if ($ms && !$db_cve->ref_Exists($ms)) {
          $db_cve->add_Reference(new cve_reference(null, 'MS', $ms_url, $ms));
        }

        if ($kb && !$db_cve->ref_Exists($kb)) {
          $db_cve->add_Reference(new cve_reference(null, 'MS', $kb_url, $kb));
        }

        $db->save_CVE(array(0 => $db_cve));
      }
    }
  }

  $stig = $db->get_Stig($ms);
  if (!$iavm = $db->get_IAVM_From_External($ms)) {
    $iavm = $db->get_IAVM_From_External($kb);
  }

  if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
    $stig = $stig[0];
  }
  else {
    $err->script_log("Failed to identify the correct STIG", E_WARNING);
  }

  // insert pdi and advisory
  if ($iavm) {
    $pdi_id = $iavm->get_PDI_ID();
  }
  elseif ($has_cve && $db_cve->get_PDI_ID()) {
    $pdi_id = $db_cve->get_PDI_ID();
  }
  elseif ($stig) {
    $pdi_id = $stig->get_PDI_ID();
  }
  else {
    // insert PDI, STIG, advisory, and CVE's
    $pdi = new pdi(null, $sev, null);
    $pdi->set_Short_Title($title);
    $pdi->set_Group_Title($title);
    $pdi_id = $db->save_PDI($pdi);

    $stig = new stig($pdi_id, $ms, $title);
    $db->add_Stig($stig);
  }

  if ($tmp = $db->get_Advisory($ms)) {
    $adv[] = $tmp[0];
  }

  if ($tmp = $db->get_Advisory("$kb")) {
    $adv[] = $tmp[0];
  }

  if (is_array($adv) && count($adv)) {
    foreach ($adv as $key => $ad) {
      //if(!$ad->get_PDI_ID()) {
      $ad->set_PDI_ID($pdi_id);
      //}

      $ad->set_Title($title);
      $ad->set_Impact($impact);
    }
  }
  else {
    if ($ms && $kb) {
      $adv = array(
        0 => new advisory($pdi_id, $ms, "", "", $ms_url),
        1 => new advisory($pdi_id, $kb, "", "", $kb_url)
      );

      $adv[0]->set_Title($title);
      $adv[0]->set_Impact($impact);

      $adv[1]->set_Title($title);
      $adv[1]->set_Impact($impact);
    }
    elseif ($ms) {
      $adv = array(
        0 => new advisory($pdi_id, $ms, "", "", $ms_url)
      );

      $adv[0]->set_Title($title);
      $adv[0]->set_Impact($impact);
    }
    elseif ($kb) {
      $adv = array(
        0 => new advisory($pdi_id, $kb, "", "", $kb_url)
      );

      $adv[0]->set_Title($title);
      $adv[0]->set_Impact($impact);
    }
  }

  $db->save_Advisory($adv);
}

$end = new DateTime();

$diff = $start->diff($end);

$err->script_log($diff->format("%H:%I:%S"));
