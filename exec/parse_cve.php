<?php

/**
 * File: parse_cve.php
 * Author: Ryan Prather
 * Purpose: To parse CVE repository retrieved from http://cve.mitre.org/data/downloads/index.html
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
 *  - Nov 21, 2016 - Added print out to display the number of new CVEs imported
 *  - Feb 15, 2017 - Retrieve and store all existing CVEs in memory to use to evaluate if one needs to be imported
 *                   This will now not update existing content.
 *  - Nov 25, 2017 - Fixed bug #342
 *  - Dec 27, 2017 - Syntax updates, and added update to load date
 */
$cmd = getopt("f:", ['debug::', 'help::']);

if (!isset($cmd['f']) || isset($cmd['help'])) {
  die(usage());
}
elseif (!file_exists($cmd['f'])) {
  die("Could not find file {$cmd['f']}\n");
}

include_once 'config.inc';
include_once "database.inc";
include_once 'helper.inc';

chdir(TMP);

set_time_limit(0);

$sys = new db();
$err = new Sagacity_Error($cmd['f']);

$existing_cves = [];

$sys->help->select("cve_db", ['cve_id']);
$cves = $sys->help->execute();
if (!is_null($cves) && is_array($cves) && count($cves)) {
  foreach ($cves as $cve) {
    $existing_cves["{$cve['cve_id']}"] = 1;
  }
}

print "Currently " . count($existing_cves) . " in the DB" . PHP_EOL;

$sys->help->update("settings", ['meta_value' => new DateTime()], [
  [
    'field' => 'meta_key',
    'op'    => '=',
    'value' => 'cve-load-date'
  ]
]);
$sys->help->execute();

$doc = new DOMDocument();
$doc->load($cmd['f']);

$items = getValue($doc, "/x:cve/x:item", null, true);
$existing = 0;
$new = 0;
$count = 0;

print "Total of {$items->length} CVEs to parse" . PHP_EOL;

if ($items->length) {
  $new_cves = [];
  $new_cve_refs = [];
  $new_cve_web = [];

  $cve_fields = [
    'cve_id', 'seq', 'status', 'phase', 'phase_date', 'desc'
  ];
  $ref_fields = [
    'cve_seq', 'source', 'url', 'val'
  ];
  $web_fields = [
    'cve_id', 'xml'
  ];

  foreach ($items as $node) {
    $name = getValue($doc, '@name', $node);

    if (!isset($existing_cves["$name"])) {
      $count++;
      $cve_xml = new DOMDocument();
      $cve_node = $cve_xml->importNode($node, true);
      $cve_xml->appendChild($cve_node);

      $pi = $cve_xml->createProcessingInstruction('xml-stylesheet', 'type="text/xsl" href="cve.xsl"');
      $cve_xml->insertBefore($pi, $cve_xml->getElementsByTagName("item")->item(0));
      $cve_xml->xmlStandalone = true;

      $tmp = str_replace(" xmlns=\"http://cve.mitre.org/cve/downloads\"", "", $cve_xml->saveXML());
      $cve_xml->loadXML($tmp);

      $refs = [];
      $type = getValue($doc, '@type', $node);
      $seq = getValue($doc, '@seq', $node);
      $desc = getValue($doc, 'x:desc', $node);
      $status = getValue($doc, 'x:status', $node);
      $phase = getValue($doc, 'x:phase', $node);
      $phase_dt_str = getValue($doc, 'x:phase/@date', $node);
      $phase_dt = new DateTime($phase_dt_str);

      $new_cves[] = [
        $name, $seq, $status, $phase, $phase_dt, $desc
      ];

      $tmp_refs = getValue($doc, 'x:refs/x:ref', $node, true);

      for ($x = 0; $x < $tmp_refs->length; $x++) {
        $refs[$x]['val'] = getValue($doc, '.', $tmp_refs->item($x));
        $refs[$x]['src'] = getValue($doc, '@source', $tmp_refs->item($x));
        $refs[$x]['url'] = getValue($doc, '@url', $tmp_refs->item($x));
      }

      foreach ($refs as $key => $ref) {
        $new_cve_refs[] = [
          $name, $ref['src'], $ref['url'], $ref['val']
        ];
      }

      $new_cve_web[] = [$name, $cve_xml->saveXML()];

      $err->script_log("new cve $name");
      $new++;
      print "*";
    }
    else {
      /*
        $sql = "REPLACE INTO `reference`.`cve_db` (`type`, `seq`, `status`, `phase`, `phase_date`, `desc`) VALUES (" .
        "'$type'," .
        "'$seq'," .
        "'{$sys->help->real_escape_string($status)}'," .
        "'{$sys->help->real_escape_string($phase)}'," .
        "'{$phase_dt->format('Y-m-d')}'," .
        "'{$sys->help->real_escape_string($desc)}') " .
        "WHERE cve_id='{$sys->help->real_escape_string($name)}'";
        $sys->help->real_query($sql);

        foreach ($refs as $key => $ref) {
        $sql = "SELECT `id` FROM `reference`.`cve_references` WHERE `cve_seq`='" .
        $sys->help->real_escape_string($name) . "' AND `source`='" .
        $sys->help->real_escape_string($ref['src']) . "'";
        $res2 = $sys->help->query($sql);
        $row2 = $res2->fetch_array(MYSQLI_ASSOC);

        if ($row2['id']) {
        $sql = "UPDATE `reference`.`cve_references` SET `url`='" . $sys->help->real_escape_string($ref['url']) .
        "', val='" . $sys->help->real_escape_string($ref['val']) . "' WHERE `id`=" . $row2['id'];
        $sys->help->real_query($sql);
        }
        else {
        $sql = "INSERT INTO `reference`.`cve_references` (`cve_seq`,`source`,`url`,`val`) VALUES ('" .
        $sys->help->real_escape_string($name) . "','" . $sys->help->real_escape_string($ref['src']) .
        "','" . $sys->help->real_escape_string($ref['url']) . "','" .
        $sys->help->real_escape_string($ref['val']) . "')";
        $sys->help->real_query($sql);
        }
        }

        $err->script_log("existing cve $name");
       */
      $existing++;
      print ".";
    }

    if (($existing + $new) % 100 == 0) {
      if (count($new_cves)) {
        $sys->help->extended_insert("cve_db", $cve_fields, $new_cves, true);
        $sys->help->execute();
      }

      if (count($new_cve_refs)) {
        $sys->help->extended_insert("cve_references", $ref_fields, $new_cve_refs, true);
        $sys->help->execute();
      }

      if (count($new_cve_web)) {
        $sys->help->extended_replace("cve_web", $web_fields, $new_cve_web);
        $sys->help->execute();
      }

      $new_cves = [];
      $new_cve_refs = [];
      $new_cve_web = [];

      print "\t" . ($existing + $new) . " completed" . PHP_EOL;

      $sys->help->update("settings", ['meta_value' => number_format((($existing + $new) / $items->length) * 100, 2)], [
        [
          'field' => 'meta_key',
          'op'    => '=',
          'value' => 'cve-progress'
        ]
      ]);
      $sys->help->execute();
    }
  }

  if (is_array($new_cves) && count($new_cves)) {
    $sys->help->extended_insert("cve_db", $cve_fields, $new_cves, true);
    $sys->help->execute();
  }

  if (is_array($new_cve_refs) && count($new_cve_refs)) {
    $sys->help->extended_insert("cve_references", $ref_fields, $new_cve_refs, true);
    $sys->help->execute();
  }

  if (is_array($new_cve_web) && count($new_cve_web)) {
    $sys->help->extended_replace("cve_web", $web_fields, $new_cve_web);
    $sys->help->execute();
  }
}

function usage() {
  print <<<EOO
Purpose: Parse the CVE file (allitems.xml) retrieved from http://cve.mitre.org/data/downloads/allitems.xml

Usage: php parse_cve.php -f={CVE filename} [--debug] [--help]

 -f={CVE filename}    The file to be parsed (allitems.xml).  Can be absolute or relative path.

 --debug              Debugging output
 --help               This screen


EOO;
}
