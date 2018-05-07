<?php

/**
 * File: export-ckl.php
 * Author: Ryan Prather <ryan.prather@cyberperspectives.com>
 * Purpose:
 * Created: Feb 20, 2017
 *
 * Copyright 2017: Cyber Perspective, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Feb 20, 2017 - File created
 *  - Mar 8, 2017 - Completed preliminary functionality
 *  - May 13, 2017 - Set default export path to TMP/ckl
 *                   Only exporting manual checklists and not export orphan findings
 *  - Oct 23, 2017 - Added a few more fields and added data to some fields that didn't have a value
 *  - Nov 25, 2017 - Fixed notice bug #346
 *  - Jan 6, 2018 - Bug fix #337 and formatting
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';
include_once 'array2xml.inc';

$db = new db();
$dt = new DateTime();

$cmd = getopt('s:t::c::h::d::', ['help::', 'debug::']);

if (!isset($cmd['s']) || !is_numeric($cmd['s'])) {
  die(usage());
}

if (isset($cmd['t'])) {
  $tgts = $db->get_Target_Details($cmd['s'], $cmd['t']);
}
elseif (isset($cmd['c'])) {
  $tgts = $db->get_Target_By_Category($cmd['c']);
}
else {
  $tgts = $db->get_Target_Details($cmd['s']);
}

if (isset($cmd['d'])) {
  if (file_exists($cmd['d'])) {
    $dest = realpath($cmd['d']) . "/";
  }
  else {
    die("Could not find destination path {$cmd['d']}");
  }
}
else {
  check_path(TMP . "/ckl", true);
  $dest = realpath(TMP . "/ckl") . "/";
}

print "Destination: $dest" . PHP_EOL;

$xml = new Array2XML();
Array2XML::$all_caps = true;
$xml->standalone = true;
$xml->formatOutput = true;

$chk_comp_count = 0;
$tgt_comp_count = 0;
$total_chk_count = 0;
$total_stigs = 0;

if ($tgt_count = count($tgts)) {
  print "Total Targets: $tgt_count" . PHP_EOL;

  foreach ($tgts as $tgt) {
    $host_ip = (is_array($tgt->interfaces) && count($tgt->interfaces) ? current($tgt->interfaces)->get_IPv4() : null);
    $host_fqdn = (is_array($tgt->interfaces) && count($tgt->interfaces) ? current($tgt->interfaces)->get_FQDN() : null);
    $host_mac = (is_array($tgt->interfaces) && count($tgt->interfaces) ? current($tgt->interfaces)->get_MAC() : null);
    //$host_mac = (count($tgt->interfaces) ? current($tgt->interfaces)->get_Mac() : null);

    print "Target: {$tgt->get_Name()}" . PHP_EOL;

    foreach ($tgt->checklists as $key => $chk) {
      if ($chk->name == 'Orphan' || $chk->type != 'manual') {
        unset($tgt->checklists[$key]);
      }
    }

    $total_chk_count += $chk_count = (is_array($tgt->checklists) ? count($tgt->checklists) : 0);

    print "Total Checklists: $chk_count" . PHP_EOL;

    foreach ($tgt->checklists as $chk) {
      print "Type: {$chk->type}\tChecklist: {$chk->name}" . PHP_EOL;
      $class = '';
      $stig_class = '';

      switch ($chk->get_Classification()) {
        case 'U':
          $class = 'UNCLASSIFIED';
          $stig_class = "Unclass";
          break;
        case 'FOUO':
          $class = 'UNCLASSIFIED//FOUO';
          $stig_class = "FOUO";
          break;
        case 'S':
          $class = 'SECRET';
          $stig_class = "Secret";
          break;
      }

      $arr = [
        'ASSET' => [
          'ASSET_TYPE'      => 'Computing',
          'HOST_NAME'       => $tgt->get_Name(),
          'HOST_IP'         => $host_ip,
          'HOST_MAC'        => $host_mac,
          'HOST_GUID'       => '',
          'HOST_FQDN'       => $host_fqdn,
          'TECH_AREA'       => '',
          'TARGET_KEY'      => '',
          'WEB_OR_DATABASE' => false,
          'WEB_DB_SITE'     => '',
          'WEB_DB_INSTANCE' => ''
        ],
        'STIGS' => [
          'iSTIG' => [
            'STIG_INFO' => [
              'SI_DATA' => [
                [
                  'SID_NAME' => 'version',
                  'SID_DATA' => $chk->get_Version()
                ],
                [
                  'SID_NAME' => 'classification',
                  'SID_DATA' => $class
                ],
                [
                  'SID_NAME' => 'customname'
                ],
                [
                  'SID_NAME' => 'stigid',
                  'SID_DATA' => $chk->get_Checklist_ID()
                ],
                [
                  'SID_NAME' => 'description',
                  'SID_DATA' => $chk->get_Description()
                ],
                [
                  'SID_NAME' => 'filename',
                  'SID_DATA' => $chk->get_File_Name()
                ],
                [
                  'SID_NAME' => 'releaseinfo',
                  'SID_DATA' => "Release: {$chk->get_Release()} Benchmark Date: {$chk->get_Date()->format("j M Y")}"
                ],
                [
                  'SID_NAME' => 'title',
                  'SID_DATA' => $chk->get_Name()
                ],
                [
                  'SID_NAME' => 'uuid',
                  'SID_DATA' => UUID::v4()
                ],
                [
                  'SID_NAME' => 'notice',
                  'SID_DATA' => 'terms-of-use'
                ],
                [
                  'SID_NAME' => 'source',
                  'SID_DATA' => 'STIG.DOD.MIL'
                ]
              ]
            ]
          ]
        ]
      ];

      $pdis = get_checklist_data($tgt, $chk);
      $stig_data = [];

      $total_stigs += $pdi_count = (is_array($pdis) ? count($pdis) : 0);
      $count = 0;

      foreach ($pdis as $pdi) {
        $find = $db->get_Finding($tgt, new stig($pdi['pdi_id'], $pdi['STIG_ID'], null));
        if (is_array($find) && count($find) && isset($find[0]) && is_a($find[0], 'finding')) {
          $find = $find[0];
        }

        $sev = 'low';
        if ($pdi['CAT'] == 'I') {
          $sev = 'high';
        }
        elseif ($pdi['CAT'] == 'II') {
          $sev = 'medium';
        }

        $ccis = preg_grep("/CCI\-/", explode(" ", $pdi['IA_Controls']));
        $cci_list = [];

        if (is_array($ccis) && count($ccis)) {
          foreach ($ccis as $cci) {
            $cci_list[] = [
              'VULN_ATTRIBUTE' => 'CCI_REF',
              'ATTRIBUTE_DATA' => $cci
            ];
          }
        }

        // decoding because check contents are already encoded
        $cc = str_replace("\\n", "<br />", htmlentities(html_entity_decode($pdi['check_contents'])));

        $stig_data = array_merge([
          [
            'VULN_ATTRIBUTE' => 'Vuln_Num',
            'ATTRIBUTE_DATA' => $pdi['VMS_ID']
          ],
          [
            'VULN_ATTRIBUTE' => 'Severity',
            'ATTRIBUTE_DATA' => $sev
          ],
          [
            'VULN_ATTRIBUTE' => 'Group_Title',
            'ATTRIBUTE_DATA' => $pdi['group_title']
          ],
          [
            'VULN_ATTRIBUTE' => 'Rule_ID',
            'ATTRIBUTE_DATA' => $pdi['SCAP_Rule']
          ],
          [
            'VULN_ATTRIBUTE' => 'Rule_Ver',
            'ATTRIBUTE_DATA' => $pdi['STIG_ID']
          ],
          [
            'VULN_ATTRIBUTE' => 'Rule_Title',
            'ATTRIBUTE_DATA' => $pdi['short_title']
          ],
          [
            'VULN_ATTRIBUTE' => 'Vuln_Discuss',
            'ATTRIBUTE_DATA' => $pdi['Description']
          ],
          [
            'VULN_ATTRIBUTE' => 'IA_Controls',
            'ATTRIBUTE_DATA' => $pdi['IA_Controls']
          ],
          [
            'VULN_ATTRIBUTE' => 'Check_Content',
            'ATTRIBUTE_DATA' => $cc
          ],
          [
            'VULN_ATTRIBUTE' => 'Fix_Text',
            'ATTRIBUTE_DATA' => htmlentities($pdi['fix_text'])
          ],
          [
            'VULN_ATTRIBUTE' => 'False_Positives',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'False_Negatives',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Documentable',
            'ATTRIBUTE_DATA' => 'false'
          ],
          [
            'VULN_ATTRIBUTE' => 'Mitigations',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Potential_Impact',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Third_Party_Tools',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Mitigation_Control',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Responsibility',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Security_Override_Guidance',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Check_Content_Ref',
            'ATTRIBUTE_DATA' => ''
          ],
          [
            'VULN_ATTRIBUTE' => 'Class',
            'ATTRIBUTE_DATA' => $stig_class
          ],
          [
            'VULN_ATTRIBUTE' => 'STIGRef',
            'ATTRIBUTE_DATA' => "{$chk->get_Name()} :: Release: {$chk->get_Release()} Benchmark Date: {$chk->get_Date()->format("j M Y")}"
          ],
          [
            'VULN_ATTRIBUTE' => 'TargetKey',
            'ATTRIBUTE_DATA' => ''
          ]
            ], $cci_list);

        $status = "Not_Reviewed";
        $notes = '';

        if (is_a($find, 'finding')) {
          $status = $find->get_Finding_Status_String();
          if ($status == 'Not a Finding' || $status == 'False Positive') {
            $status = "NotAFinding";
          }
          elseif($status == 'Exception') {
              $status = 'Open';
          }
          else {
            $status = str_replace(" ", "_", $status);
          }
          $notes = $find->get_Notes();
        }

        $arr['STIGS']['iSTIG']['VULN'][] = [
          'STIG_DATA'              => $stig_data,
          'STATUS'                 => $status,
          'FINDING_DETAILS'        => $notes,
          'COMMENTS'               => '',
          'SEVERITY_OVERRIDE'      => '',
          'SEVERITY_JUSTIFICATION' => ''
        ];

        $count++;

        printf("\r%.2f%%", ($count / $pdi_count) * 100);
      }

      print PHP_EOL;

      $file = $xml->createXML('CHECKLIST', $arr);

      $file->save("{$dest}{$tgt->get_Name()}_{$chk->get_Checklist_ID()}_{$chk->get_type()}_{$dt->format("Ymd")}.ckl");
    }
  }
}

print <<<EOO

Total Targets: $tgt_count
Total Checklists: $total_chk_count
Total STIGs: $total_stigs

EOO;

/**
 *
 * @global db $db
 *
 * @param target $tgt
 * @param checklist $chk
 *
 * @return mixed
 */
function get_checklist_data($tgt, $chk) {
  if (!is_a($tgt, 'target') || !is_a($chk, 'checklist')) {
    return;
  }

  global $db;

  $db->help->select("sagacity.pdi", ["pdi.*", "pcl.*", "s.description AS 'Description'"], [
    [
      'field' => 'tc.tgt_id',
      'op'    => '=',
      'value' => $tgt->get_ID()
    ],
    [
      'field'  => 'tc.chk_id',
      'op'     => '=',
      'value'  => $chk->id,
      'sql_op' => 'AND'
    ]
      ], [
    'table_joins' => [
      "JOIN sagacity.pdi_checklist_lookup pcl ON pcl.pdi_id = pdi.pdi_id",
      "JOIN sagacity.target_checklist tc ON tc.chk_id = pcl.checklist_id",
      "JOIN sagacity.stigs s ON s.pdi_id = pdi.pdi_id"
    ]
  ]);
  $pdis = $db->help->execute();

  return $pdis;
}

/**
 * Function retrieve
 *
 * @global db $db
 *
 * @param target $tgt
 * @param checklist $chk
 *
 * @return mixed
 */
function get_finding_data($tgt, $chk) {
  global $db;
  $ret = [];

  return $ret;
}

/**
 * Usage output
 */
function usage() {
  print <<<EOO
Purpose: This script was written to be able to export CKL files from the data contained in the database.

Usage: php export-ckl.php [-d={destination}] -s={ste id} [-c={category id}] [-t={target id}] [-h|--help]

 -s={STE ID}        Export a CKL for each assigned checklist for ALL targets in this ST&E
 -c={Category ID}   Export CKL files for all targets contained in this Category
 -t={Target ID}     Export CKL file for each assigned checklist for this target

 -d={destination}   Location of where you want the files saved

 -h|--help          This screen
 --debug            Debugging output

EOO;
}
