<?php

/**
 * File: parse_iavm.php
 * Author: Ryan Prather
 * Purpose: To parse IAVM files retrieved from https://iavm.csd.disa.mil
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
 *  - Sep 1, 2016 - Copyright Updated and converted to constants
 */
$cmd = getopt("d:f::", array('debug::', 'help::'));

if (!isset($cmd['f']) || !isset($cmd['s']) || isset($cmd['help'])) {
  usage();
  exit;
}

include_once 'config.inc';
include_once "database.inc";
include_once 'helper.inc';

chdir(DOC_ROOT . "/tmp");
set_time_limit(0);

$sys = new db();

$db = new mysqli(DB_SERVER, 'web', db::decrypt_pwd(), 'sagacity');
if ($db->connect_errno) {
  die($db->connect_error);
}

if (!isset($cmd['d'])) {
  die("Did not include the directory the files are in");
}

chdir($cmd['d']);

if (isset($cmd['f'])) {
  $files = array(0 => $cmd['f']);
}
else {
  $files = glob("*.xml");
}

foreach ($files as $file) {
  print $file . PHP_EOL;
  $doc = new DOMDocument();
  $doc->load($file);

  $pi = $doc->createProcessingInstruction('xml-stylesheet', 'type="text/xsl" href="iavm.xsl"');
  $doc->insertBefore($pi, $doc->getElementsByTagName("iavmNotice")->item(0));
  $doc->xmlStandalone = true;

  $tmp = $doc->saveXML();
  $tmp = str_replace(" xmlns=\"http://iavm.csd.disa.mil/schemas/IavmNoticeSchema/1.2\"", "", $tmp);
  $doc->loadXML($tmp);

  // root node values (iavm_notice table)
  $id = getValue($doc, '/iavmNotice/@noticeId');
  $xmlurl = getValue($doc, '/iavmNotice/xmlUrl');
  $htmlurl = getValue($doc, '/iavmNotice/htmlUrl');
  $noticeNumber = getValue($doc, '/iavmNotice/iavmNoticeNumber');
  $title = getValue($doc, '/iavmNotice/title');
  $type = getValue($doc, '/iavmNotice/type');
  $state = getValue($doc, '/iavmNotice/state');
  $lastUpdated = getValue($doc, '/iavmNotice/lastUpdated');
  $releaseDate = getValue($doc, '/iavmNotice/releaseDate');
  $supersedes = getValue($doc, '/iavmNotice/supersedes');
  $execSummary = getValue($doc, '/iavmNotice/executiveSummary');
  $fixAction = getValue($doc, '/iavmNotice/fixAction');
  $note = getValue($doc, '/iavmNotice/note');
  $vulnAppsSysAndCntrmsrs = getValue($doc, '/iavmNotice/vulnAppsSysAndCntrmsrs');
  $knownExploits = getValue($doc, '/iavmNotice/knownExploits');
  $stigFindingSeverity = getValue($doc, '/iavmNotice/vms/stigFindingSeverity');

  // iavm_tech_overview
  $techOverview = getValue($doc, '/iavmNotice/techOverview', null, true);

  // iavm_references
  $references = getValue($doc, '/iavmNotice/references/reference', null, true);

  // iavm_bids
  $bids = getValue($doc, '/iavmNotice/deepSightBids/bid', null, true);

  // iavm_patches
  $patches = getValue($doc, '/iavmNotice/patches/patch', null, true);

  // iavm_mitigations
  $mitHeader = getValue($doc, '/iavmNotice/tempMitStrat/header');
  $mitBody = getValue($doc, '/iavmNotice/tempMitStrat/body');

  $doc->formatOutput = true;
  $doc->preserveWhiteSpace = true;
  //print $doc->saveXML();

  if (is_array($supersedes)) {
    $supersedes = implode(',', $supersedes);
  }

  $stig = $sys->get_Stig($noticeNumber);
  if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
    $stig = $stig[0];
    $pdi_id = $stig->get_PDI_ID();
  }
  else {
    $pdi = new pdi(null, $stigFindingSeverity, $lastUpdated);
    $pdi->set_Short_Title($title);
    $pdi->set_Group_Title($title);
    $pdi->set_Description($execSummary);
    // print_r($pdi);
    $pdi_id = $sys->save_PDI($pdi);

    $stig = new stig($pdi_id, $noticeNumber, $execSummary);
    // print_r($stig);
    $sys->add_Stig($stig);
  }

  $last_updated_dt = new DateTime($lastUpdated);
  $release_date_dt = new DateTime($releaseDate);

  $iavm = $sys->get_IAVM($noticeNumber);
  if (is_null($iavm)) {
    $sys->help->insert("sagacity.iavm_notices", [
      'pdi_id'                 => $pdi_id,
      'noticeId'               => $id,
      'xmlUrl'                 => $xmlurl,
      'htmlUrl'                => $htmlurl,
      'file_name'              => basename($file),
      'iavmNoticeNumber'       => $noticeNumber,
      'title'                  => $title,
      'type'                   => $type,
      'state'                  => $state,
      'lastUpdated'            => $last_updated_dt->format(MYSQL_D_FORMAT),
      'releaseDate'            => $release_date_dt->format(MYSQL_D_FORMAT),
      'supersedes'             => $supersedes,
      'executiveSummary'       => $execSummary,
      'fixAction'              => $fixAction,
      'note'                   => $note,
      'vulnAppsSysAndCntrmsrs' => $vulnAppsSysAndCntrmsrs,
      'stigFindingSeverity'    => $stigFindingSeverity,
      'knownExploits'          => $knownExploits
        ], true);

    if (!$sys->help->execute()) {
      error_log("file: $file" . PHP_EOL . $db->error . PHP_EOL . $ins_sql);
      continue;
      //die;
    }
  }

  if ($bids->length) {
    foreach ($bids as $bid) {
      if ($res = $db->query(
          "SELECT COUNT(1) as 'cnt' FROM sagacity.iavm_bids WHERE iavm_notice_id = $id AND bid = '" . $bid->textContent .
          "'")) {
        if ($res->num_rows) {
          $row = $res->fetch_array(MYSQLI_ASSOC);
          print "existing bid: $bid->textContent" . PHP_EOL;
        }
        else {
          $sql = "INSERT INTO sagacity.iavm_bids (iavm_notice_id, bid) VALUES ($id, $bid->textContent)";
          $db->real_query($sql);
          print "new bid: $bid->textContent" . PHP_EOL;
        }
      }
      else {
        error_log($db->error);
      }
    }
  }

  if ($references->length) {
    foreach ($references as $ref) {
      $url = getValue($doc, "url", $ref);
      $title = getValue($doc, "title", $ref);
      $type = getValue($doc, "type", $ref);

      $res = $db->query(
          "SELECT id FROM sagacity.iavm_references WHERE iavm_notice_id = $id AND url='" .
          $db->real_escape_string($url) . "'");

      if ($res->num_rows) {
        $row = $res->fetch_array(MYSQLI_ASSOC);
        $sql = "UPDATE sagacity.iavm_references SET title = '" . $db->real_escape_string($title) .
            "' WHERE id = " . $row['id'];
        $db->real_query($sql);
        print "existing reference: " . $title . " (" . $row['id'] . ")" . PHP_EOL;
      }
      else {
        $sql = "INSERT INTO sagacity.iavm_references (iavm_notice_id, title, url) VALUES ($id, '" .
            $db->real_escape_string($title) . "','" . $db->real_escape_string($url) . "')";
        $db->real_query($sql);
        // print "db error: ".$db->error.PHP_EOL;
        print "new reference: " . $title . PHP_EOL;
      }

      $matches = array();
      if (preg_match("/microsoft\.com.*\/([\d]+)/i", $url, $matches) ||
          preg_match("/(MS[\d]+\-[\d]+)/", $title, $matches)) {
        if (is_numeric($matches[1])) {
          $matches[1] = "KB" . $matches[1];
        }
        $adv = new advisory($pdi_id, $matches[1], "", "", $url);
        $sys->save_Advisory(array(
          0 => $adv
        ));
      }
    }
  }

  if ($techOverview->length) {
    foreach ($techOverview as $to) {
      $details = getValue($doc, "details", $to);
      if ($details) {
        $res = $db->query(
            "SELECT id FROM sagacity.iavm_tech_overview WHERE iavm_notice_id = $id AND details='" .
            $db->real_escape_string($details) . "'");
        $row = $res->fetch_array(MYSQLI_ASSOC);

        if ($row['id']) {
          print "existing overview for $id" . PHP_EOL;
        }
        else {
          $sql = "INSERT INTO sagacity.iavm_tech_overview (iavm_notice_id, details) VALUES ($id, '" .
              $db->real_escape_string($details) . "')";
          $db->real_query($sql);
          print "new overview" . PHP_EOL;
        }
      }

      $entries = getValue($doc, "entry", $to, true);
      if ($entries->length) {
        foreach ($entries as $entry) {
          $entry_title = getValue($doc, "title", $entry);
          $entry_desc = getValue($doc, "description", $entry);

          if (substr($entry_title, 0, 3) == 'CVE') {
            print "CVE: $entry_title" . PHP_EOL;
            $sql = "REPLACE INTO sagacity.iavm_to_cve (noticeId, cve_id) VALUES (" . $id . "," . "'" .
                $db->real_escape_string($entry_title) . "')";

            $db->real_query($sql);
          }
          else {
            Sagacity_Error::err_handler("Entry title: $entry_title in file $file");
          }
        }
      }
    }
  }

  if ($patches->length) {
    foreach ($patches as $patch) {
      $title = getValue($doc, "title", $patch);
      $type = getValue($doc, "type", $patch);
      $url = getValue($doc, "url", $patch);

      $res = $db->query(
          "SELECT id FROM sagacity.iavm_patches WHERE iavm_notice_id = $id AND url = '" .
          $db->real_escape_string($url) . "'");
      $row = $res->fetch_array(MYSQLI_ASSOC);

      if ($row['id']) {
        $sql = "UPDATE sagacity.iavm_patches SET `type` = '" . $db->real_escape_string($type) .
            "', `title` = '" . $db->real_escape_string($title) . "' WHERE id = " . $row['id'];
        $db->real_query($sql);
        print "existing patch: $title (" . $row['id'] . ")" . PHP_EOL;
      }
      else {
        $sql = "INSERT INTO sagacity.iavm_patches (iavm_notice_id, `type`, title, url) VALUES ($id, '" .
            $db->real_escape_string($type) . "','" . $db->real_escape_string($title) . "','" .
            $db->real_escape_string($url) . "')";
        $db->real_query($sql);
        print "new patch: $title" . PHP_EOL;
      }

      $matches = array();
      if (preg_match("/(KB[\d]+)|(MS[\d]+\-[\d]+)/i", $title, $matches)) {
        $adv = new advisory($pdi_id, $matches[1], "", "", $url);
        $sys->save_Advisory(array(
          0 => $adv
        ));
      }
    }
  }

  if ($mitHeader) {
    $res = $db->query(
        "SELECT id FROM sagacity.iavm_mitigations WHERE iavm_notice_id = $id AND header = '" .
        $db->real_escape_string($mitHeader) . "'");
    $row = $res->fetch_array(MYSQLI_ASSOC);

    if ($row['id']) {
      $sql = "UPDATE sagacity.iavm_mitigations SET body = '" . $db->real_escape_string($mitBody) .
          "' WHERE id = " . $row['id'];
      $db->real_query($sql);
      print "existing mitigation: " . $row['id'] . PHP_EOL;
    }
    else {
      $sql = "INSERT INTO sagacity.iavm_mitigations (iavm_notice_id, header, body) VALUES ($id, '" .
          $db->real_escape_string($mitHeader) . "','" . $db->real_escape_string($mitBody) . "')";
      $db->real_query($sql);
      print "new mitigation: $mitHeader" . PHP_EOL;
    }
  }

  if (!$doc->save(DOC_ROOT . "/reference/iavms/$file")) {
    print "error saving" . PHP_EOL;
    die;
  }
}

function usage() {
  print <<<EOO
Purpose: To import an IAVM file and populate/update the database

Usage: php parse_iavm.php -d={IAVM Directory} [-f={XCCDF result file}] [--debug] [--help]

 -d={IAVM directory}    The directory to import the files from.  This will crawl the directory and import all the IAVMs
 -f={XCCDF file}        The IAVM file specifically

 --debug                Debugging output
 --help                 This screen

EOO;
}
