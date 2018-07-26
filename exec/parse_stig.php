<?php

/**
 * File: parse_stig.php
 * Author: Ryan Prather
 * Purpose: To parse a STIG file
 * Created: Jul 9, 2014
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
 *  - Jul 9, 2014 - File created
 *  - Jun 3, 2015 - Copyright Updated and converted to constants
 *  - Oct 24, 2016 - Updated E_DEBUG constant
 *  - Nov 7, 2016 - Make sure that /reference/stigs directory is present
 *  - Feb 15, 2017 - Formatting and migrated some SQL to db_helper
 *  - Mar 3, 2017 - Fixed a few bugs to get the code processing the latest STIGs
 *  - Apr 5, 2017 - Fixed bug parsing software correctly
 *  - Jun 27, 2017 - Fixed bug when parsing VVoIP file and cleanup
 *  - Jun 29, 2017 - Refactored a few lines of code and fixed bug #262. Also, changed default CCI to 002613 if there is no other control link
 *  - Jul 13, 2017 - Fixed bug #273/4
 *  - Jul 23, 2017 - MAS Added comments
 *  - Aug 28, 2017 - Added die for draft stigs
 *  - Dec 27, 2017 - Added up date for load date
 *  - May 10, 2018 - Starting to migrate logging and fixed install status bar issues (#403)
 */
$cmd = getopt("f:", ['debug::', 'ia_reset::', 'draft::', 'help::']);

if (!isset($cmd['f']) || isset($cmd['help'])) {
  die(usage());
}

set_time_limit(0);
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';
require_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

$stream = new StreamHandler("php://output", Logger::INFO);
$stream->setFormatter(new LineFormatter("%datetime% %level_name% %message%", "H:i:s.u"));
/*
$log = new Logger("parse_stig");
$log->pushHandler(new StreamHandler(LOG_PATH . "/" . basename($cmd['f']) . ".log", LOG_LEVEL));
$log->pushHandler($stream);
*/

chdir(DOC_ROOT . "/exec");
// Capture start time for performance metrics
$start = new DateTime();

// Check to make sure file argument exists and is an XCCDF file
if (!file_exists($cmd['f'])) {
  Sagacity_Error::err_handler("XML file not found {$cmd['f']}", E_ERROR);
}
elseif (strpos(strtolower($cmd['f']), "xccdf") === false) {
  Sagacity_Error::err_handler("Only compatible with XCCDF file formats", E_ERROR);
}

// Verify our STIG reference directory exists
check_path(DOC_ROOT . "/reference/stigs");

// open db connection
$db = new db();

$content = str_replace(["â€™", "â€“", "â€œ", "â€"], ["'", "-", '"', '"'], file_get_contents($cmd['f']));
file_put_contents($cmd['f'], $content);

// open xml file
$base_name = basename($cmd['f']);
$perc_comp = 0;
$new_count = 0;
$updated_count = 0;
$log = new Sagacity_Error($base_name);

// Create and update parse job details
$db->help->select_count("sagacity.catalog_scripts", [
  [
    'field' => 'file_name',
    'op'    => '=',
    'value' => $base_name
  ]
]);
$exists = $db->help->execute();

if (!$exists) {
  $db->add_Catalog_Script($base_name);
}

$db->update_Catalog_Script($base_name, ['name' => 'pid', 'value' => getmypid()]);
$db->help->update("sagacity.settings", ['meta_value' => new DateTime()], [
  [
    'field' => 'meta_key',
    'op'    => '=',
    'value' => 'stig-load-date'
  ]
]);
$db->help->execute();
$tmp = $db->get_Stig();
$stigs = [];
foreach ($tmp as $s) {
  $stigs["{$s->get_ID()}"] = $s;
}

print "Currently " . count($stigs) . " in the DB" . PHP_EOL;
// Load XML into DOMDocument
$xml = new DOMDocument();
if (!$xml->load($cmd['f'])) {
  $log->script_log("Error opening file", E_ERROR);
}

// Get regexes used to assess the STIG for known applicable software products
$regex_arr = $db->get_Regex_Array("checklist");
if (is_array($regex_arr) && !count($regex_arr)) {
  die("There are no regular expressions to detect checklist software");
}
$csv_file = substr($cmd['f'], 0, -3) . "csv";
$csv = fopen($csv_file, "w");

fputcsv($csv, ["STIG_ID", "VMS_ID", "CAT", "IA_Controls", "Short_Title", "Status", "Notes", "Check_Contents", "SV_Rule_ID", "Oval_ID"]);

// get checklist data
$checklist = [];
$checklist['id'] = str_replace("-", '.', getValue($xml, '@id'));
$checklist['status'] = getValue($xml, "/x:Benchmark/x:status");

// Skip draft STIGs if debug flag is not set. @Ryan: Shouldn't this be checking the draft flag instead of debug?
if (!isset($cmd['draft'])) {
  if (strtolower($checklist['status']) == 'draft') {
    $db->update_Catalog_Script($base_name, ["name" => "status", "value" => "SKIPPED"]);
    fclose($csv);
    unset($xml);
    unlink($cmd['f']);
    $log->script_log("Skipping since this is a draft STIG" . PHP_EOL, E_NOTICE);

    die();
  }
}
$checklist['status_date'] = getValue($xml, "/x:Benchmark/x:status", null, true)->item(0)->getAttribute('date');
$checklist['status_date'] = new DateTime($checklist['status_date']);
$checklist['ver'] = getValue($xml, "/x:Benchmark/x:version");
$checklist['plain_text'] = getValue($xml, "/x:Benchmark/x:plain-text");

// Attempt to identify the software product referenced by the STIG
$checklist['software'] = software::identify_Software($regex_arr, $checklist['id']);

if (isset($cmd['debug'])) {
  $log->script_log(print_r($checklist['software'], true), E_DEBUG);
}

// If no matching software is found, default to "generic"
if (!count($checklist['software'])) {
  $log->script_log("Could not identify software, setting as Generic/Generic", E_NOTICE);
  $checklist['software'][] = [
    'man'  => 'Generic',
    'name' => 'Generic',
    'ver'  => '-',
    'sp'   => null,
    'type' => false
  ];
}

// Convert identified software to a software object.
$sw_arr = software::toSoftwareFromArray($checklist['software']);

if (isset($cmd['debug'])) {
  $log->script_log(print_r($sw_arr, true), E_DEBUG);
}

foreach ($sw_arr as $key => $sw) {
  do {
    $cpe = "cpe:/" . ($sw->is_OS() ? "o" : "a") . ":{$sw->get_Man()}:{$sw->get_Name()}" .
        ($sw->get_Version() != '-' ? ":{$sw->get_Version()}" : "");
    $cpe = str_replace(
        [" ", "(", ")"], ["_", "%28", "%29"], strtolower($cpe)
    );

    $db_sw = $db->get_Software($cpe);

    if (!count($db_sw) && !count($checklist['software'])) {
      $sw->reduce_CPE();
    }
    elseif (is_array($db_sw) && count($db_sw) == 1 && $db_sw[0]->get_Version() == '-' && !preg_match("/generic/", $sw->get_CPE())) {
      $checklist['software'] = array_merge($checklist['software'], $db_sw);
      $sw->reduce_CPE();
      $db_sw = [];
    }
    else {
      break;
    }

    if (isset($cmd['debug'])) {
      $log->script_log("$cpe found " . count($db_sw), E_DEBUG);
    }
  }
  while (!count($db_sw));

  $checklist['software'] = array_merge($checklist['software'], $db_sw);
}

foreach ($checklist['software'] as $key => $sw) {
  if (!is_a($sw, 'software')) {
    unset($checklist['software'][$key]);
  }
}

$match = [];

if (preg_match('/Release: (\d+\.\d+|\d+)/', $checklist['plain_text'], $match)) {
  $checklist['rel'] = $match[1];
}
else {
  $checklist['rel'] = '';
}

// Get the date of the benchmark in the 'plain-text' element or set to 'status-date' if match fails
if (preg_match('/Benchmark Date: (.*)$/', $checklist['plain_text'], $match)) {
  $checklist['benchmark_date'] = new DateTime($match[1]);
}
else {
  $checklist['benchmark_date'] = $checklist['status_date'];
}

// Get the STIG title and convert common acronyms (STIG, IAVM, and SRG)
$checklist['title'] = getValue($xml, "/x:Benchmark/x:title");
$checklist['title'] = preg_replace("/Security Technical Implementation Guide/i", "STIG", $checklist['title']);
$checklist['title'] = preg_replace("/STIG \(?STIG\)?/i", "STIG", $checklist['title']);
$checklist['title'] = preg_replace("/Information Assurance Vulnerabilities/i", "IAVM", $checklist['title']);
$checklist['title'] = preg_replace("/Security Requirements Guide/i", "SRG", $checklist['title']);
$checklist['desc'] = getValue($xml, "/x:Benchmark/x:description");

// Set checklist type to benchmark, iavm, policy, or manual based on file name
$checklist['type'] = 'benchmark';

if (preg_match('/IAVM/i', $base_name)) {
  $checklist['type'] = 'iavm';
}
elseif (preg_match('/policy|srg/i', $base_name)) {
  $checklist['type'] = 'policy';
}
elseif (preg_match('/manual/i', $base_name)) {
  $checklist['type'] = 'manual';
}

// Capture version release in filename as sometimes it doesn't match the plain_text element
if (preg_match('/V(\d+)R/', $base_name, $match)) {
  $checklist['file_ver'] = $match[1];
}
else {
  $checklist['file_ver'] = 0;
}

if (preg_match('/V\d+R(\d+|\d+\.\d+)/', $base_name, $match)) {
  $checklist['file_rel'] = $match[1];
}
else {
  $checklist['file_rel'] = 0;
}

// Assign ver and rel to whichever value is greater (filename or xml)
$checklist['ver'] = $checklist['file_ver'] > $checklist['ver'] ? $checklist['file_ver'] : $checklist['ver'];
$checklist['rel'] = $checklist['file_rel'] > $checklist['rel'] ? $checklist['file_rel'] : $checklist['rel'];

if (isset($cmd['debug'])) {
  $log->script_log("Checklist:" . PHP_EOL . print_r($checklist, true), E_DEBUG);
}

// Query the db to see if the checklist is already in there
$db->help->select("sagacity.checklist", ['id'], [
  [
    'field' => 'checklist_id',
    'op'    => '=',
    'value' => $checklist['id']
  ],
  [
    'field'  => 'release',
    'op'     => '=',
    'value'  => $checklist['rel'],
    'sql_op' => 'AND'
  ],
  [
    'field'  => 'ver',
    'op'     => '=',
    'value'  => $checklist['ver'],
    'sql_op' => 'AND'
  ],
  [
    'field'  => 'type',
    'op'     => '=',
    'value'  => $checklist['type'],
    'sql_op' => 'AND'
  ]
]);
$chk = $db->help->execute();

// If checklist is found, retrieve it
if ($chk) {
  $chk = $db->get_Checklist($chk['id']);

  if (count($chk) && is_a($chk[0], 'checklist')) {
    $chk = $chk[0];
  }
  // Update software products associated with this checklist
  $sw_arr = [];
  foreach ($checklist['software'] as $sw) {
    $sw_arr[] = [$chk->get_ID(), $sw->get_ID()];
  }

  if (is_array($sw_arr) && count($sw_arr)) {
    $db->help->extended_insert("sagacity.checklist_software_lookup", ['chk_id', 'sw_id'], $sw_arr, true);
    if (!$db->help->execute()) {
      $db->debug(E_WARNING);
    }
  }

  if (isset($cmd['debug'])) {
    $log->script_log(print_r($chk, true), E_DEBUG);
  }
}
else {
  // If checklist is not found, add checklist to DB
  $chk = new checklist(
      null, $checklist['id'], $checklist['title'], $checklist['desc'], $checklist['status_date'], $base_name, $checklist['ver'], $checklist['rel'], ($checklist['type'] == 'iavm' ? 'IAVM' : ucfirst($checklist['type'])), null
  );
  $chk->add_SW($checklist['software']);

  if (!($chk->id = $db->save_Checklist($chk))) {
    $log->script_log("Failed to save new checklist ({$chk->get_Name()})", E_ERROR);
  }
}

if (!$chk->id) {
  $log->script_log("Could not find or create checklist", E_ERROR);
}

if (isset($cmd['debug'])) {
  $log->script_log("Found checklist:" . PHP_EOL . print_r($chk, true), E_DEBUG);
}
// Get the collection of STIG rules i.e., <Group> elements
$groups = getValue($xml, '/x:Benchmark/x:Group', null, true);

$log->script_log("$groups->length STIGs to run", E_DEBUG);

$db->update_Catalog_Script($base_name, ['name' => 'stig_count', 'value' => $groups->length]);

print "File: $base_name" . PHP_EOL;
print "Total: $groups->length" . PHP_EOL;

// Iterate over each group element processing the attributes/children
foreach ($groups as $group) {
  // Initialize local variables to hold parsed data
  $new = false;
  $references = [];
  $ias = [];
  $ia_controls = '';
  $perc_comp++;
  $vms_id = $group->getAttribute('id');

  // the ".//" indicates that we are starting at the current node ($group) and looking in all child nodes for the "title" and "description" nodes
  $group_title = getValue($xml, './/x:title', $group, true)->item(0)->nodeValue;
  $group_desc = getValue($xml, './/x:description', $group);

  // Get the Rule DOMElement
  $group_rule = getValue($xml, 'x:Rule', $group, true)->item(0);

  $sv_rule = $group_rule->getAttribute('id');

  // Get the severity category and convert to an integer from one to three
  $cat = 0;
  if ($group_rule->getAttribute('severity') == 'high') {
    $cat = 1;
  }
  elseif ($group_rule->getAttribute('severity') == 'medium') {
    $cat = 2;
  }
  elseif ($group_rule->getAttribute('severity') == 'low') {
    $cat = 3;
  }

  $rule_check_content = '';
  $rule_ident = getValue($xml, ".//x:ident", $group_rule, true);
  $rule_stig_id = getValue($xml, './/x:version', $group_rule);
  $rule_title = textCleanup(getValue($xml, './/x:title', $group_rule));
  $rule_desc = textCleanup(getValue($xml, './/x:description', $group_rule));
  $check_content_nodes = getValue($xml, './/x:check-content', $group_rule, true);
  $rule_check_ref = getValue($xml, './/x:check-content-ref', $group_rule, true);
  $fix_text = getValue($xml, './/x:fixtext', $group_rule);
  if ($rule_check_ref->length) {
    $oval_id = $rule_check_ref->item(0)->getAttribute('name');
  }
  else {
    $oval_id = '';
  }
  $match = [];
  $discussion = "";
  if (preg_match("/<VulnDiscussion>(.*)<\/VulnDiscussion>/", html_entity_decode($rule_desc), $match)) {
    $discussion = $match[1];
  }

  // Remove unnecessary whitespace from and concatenate check content
  if ($check_content_nodes->length > 0) {
    for ($x = 0; $x < $check_content_nodes->length; $x++) {
      $rule_check_content .= ($x + 1) . ") " . textCleanup($check_content_nodes->item($x)->textContent) . PHP_EOL;
    }

    $rule_check_content = trim($rule_check_content, PHP_EOL);
  }

  //$log->script_log("STIG ID: $rule_stig_id", E_DEBUG);
  // Assign default category if not provided and add comment indicating such to rule description
  if (!$cat) {
    $cat = 2;
    $discussion .= " :CAT SET BY SCRIPT";
  }

  // Extract and append potential impacts tag content from/to rule description
  if (preg_match('/<PotentialImpacts>(.*)<\/PotentialImpacts>/', $rule_desc, $match)) {
    $discussion .= "\n{$match[1]}";
  }

  if (!$rule_stig_id) {
    if ($vms_id == 'V0001073' || $vms_id == 'V-1073') {
      $rule_stig_id = '2.005';
    }
    elseif ($vms_id == 'V0001103' || $vms_id == 'V-1103') {
      $rule_stig_id = '4.010';
    }
  }

  // Check if rule is an IAVM
  $is_iavm = false;
  if (preg_match('/([\d]+\-[ABT]\-[\d]+)/', $rule_title, $match)) {
    $references[] = $match[1];
    if (!$rule_stig_id) {
      $rule_stig_id = $match[1];
      $is_iavm = true;
    }
  }
  // Check if rule is an MS bulletin
  if (preg_match('/(MS[\d]\-[\d]+)/', $rule_title, $match)) {
    $references[] = $match[1];
    if (!$rule_stig_id) {
      $rule_stig_id = $match[1];
    }
  }

  // If no STIG ID found, set to "No Reference"
  if (!$rule_stig_id) {
    error_log("Could not find stig id for group id $vms_id");
    $rule_stig_id = 'No Reference';
  }

  $searchstring = [
    'MS[\d]+\-[\d]+',
    'CVE\-[\d\-]+',
    '[^E]CAN\-[\d\-]+'
  ];

  foreach ($searchstring as $string) {
    if (preg_match_all("/($string)/", $rule_desc, $match)) {
      for ($x = 0; $x < count($match[0]); $x++) {
        if (!in_array($match[0][$x], $references)) {
          $references[] = $match[0][$x];
        }
      }
    }

    if (preg_match_all("/($string)/", $rule_check_content, $match)) {
      for ($x = 0; $x < count($match[0]); $x++) {
        if (!in_array($match[0][$x], $references)) {
          $references[] = $match[0][$x];
        }
      }
    }
  }

  $safe_rule_title = preg_replace('/[\(\)\[\]\.\+\*]/', '', $rule_title);

  $ia_ctrl = [];

  if (isset($stigs["$rule_stig_id"])) {
    print ".";
    $updated_count++;
    $db_stig = $stigs["$rule_stig_id"];
    $db_pdi = $db->get_PDI($db_stig->get_PDI_ID(), $chk->get_ID());
    $db_pdi->set_Group_Title($group_title);
    $db_pdi->set_Short_Title($rule_title);
    $db_pdi->set_Check_Contents($rule_check_content);
    $db_pdi->set_Fix_Text($fix_text);
    $pdi_id = $db_pdi->get_ID();

    if ($db_pdi->get_Category_Level() != $cat) {
      $db_pdi->set_Catetgory_Level($cat);
      $db_pdi->set_Update($checklist['benchmark_date']->format("Y-m-d"));
    }

    $db->save_PDI($db_pdi, $chk);
  }
  else {
    print "*";
    // add pdi
    $new_count++;
    $db_pdi = new pdi(null, $cat, $checklist['benchmark_date']->format('Y-m-d'));
    $db_pdi->set_Group_Title($group_title);
    $db_pdi->set_Short_Title($rule_title);
    $db_pdi->set_Check_Contents($rule_check_content);
    $db_pdi->set_Fix_Text($fix_text);
    $pdi_id = $db->save_PDI($db_pdi, $chk);
    $db_pdi->set_ID($pdi_id);

    // add stig
    $db_stig = new stig($pdi_id, $rule_stig_id, $discussion);
    $db->add_Stig($db_stig);

    $new = true;
  }

  if (!empty($vms_id)) {
    $vms_id = preg_replace("/^V0+/", "V-", $vms_id);
    $gd = $db->get_GoldDisk($vms_id);
    if (empty($gd)) {
      $gd = new golddisk($pdi_id, $vms_id, $rule_title);
      $db->save_GoldDisk($gd);
    }
  }

  /*
    if (!$db->save_Check_Contents($db_pdi, $chk, $rule_check_content, $fix_text)) {
    $log->script_log("Couldn't save check contents for STIG ID: {$db_stig->get_ID()} in checklist {$chk->get_Checklist_ID()} ({$chk->get_File_Name()})\n", E_ERROR);
    }
   */

  $new_controls = [];
  $control_fields = ['pdi_id', 'type', 'type_id'];

  if (preg_match("/<IAControls>(.*)<\/IAControls>/i", $rule_desc, $match)) {
    $ia_controls = (isset($match[1]) && !empty($match[1]) ? $match[1] : null);

    if (preg_match("/DCSQ|ECMT/i", $ia_controls)) {
      $new_controls[] = [
        $pdi_id,
        'VIVM',
        '1'
      ];
      $ias[] = "VIVM-1";
    }
    elseif ($ia_controls) {
      $split_ias = preg_split('/\, ?/', $ia_controls);

      foreach ($split_ias as $ia) {
        $split_ia = explode("-", $ia);

        if (isset($split_ia[0]) && $split_ia[1]) {
          $ias[] = "{$split_ia[0]}-{$split_ia[1]}";
          $new_controls[] = [
            $pdi_id,
            $split_ia[0],
            $split_ia[1]
          ];
        }
      }
    }
  }
  elseif ($rule_ident->length) {
    for ($x = 0; $x < $rule_ident->length; $x++) {
      if (substr($rule_ident->item($x)->textContent, 0, 3) == 'CCI') {
        $split_ia = explode("-", $rule_ident->item($x)->textContent);

        if (isset($split_ia[0]) && isset($split_ia[1])) {
          $ias[] = "{$split_ia[0]}-{$split_ia[1]}";
          $new_controls[] = [
            $pdi_id,
            $split_ia[0],
            $split_ia[1]
          ];
        }
      }
    }
  }
  else {
    if ($is_iavm) {
      $ias[] = "CCI-002613";
      $new_controls[] = [
        $pdi_id,
        "CCI",
        "002613"
      ];
    }
    else {
      $ias[] = "CCI-000366";
      $new_controls[] = [
        $pdi_id,
        "CCI",
        "000366"
      ];
    }
  }

  //$db_ia = $db->get_IA_Controls_By_PDI($db_pdi->get_ID());
  if (isset($cmd['ia_reset']) && !$new) {
    // delete ia controls
    $db->help->delete("sagacity.ia_controls", [
      [
        'field' => 'pdi_id',
        'op'    => '=',
        'value' => $pdi_id
      ]
    ]);
    $db->help->execute();
  }

  if (count($new_controls)) {
    $db->help->extended_replace("sagacity.ia_controls", $control_fields, $new_controls);
    if (!$db->help->execute()) {
      $db->help->debug(E_ERROR);
    }
  }

  $sv = new sv_rule($pdi_id, $sv_rule);
  $db->save_SV_Rule(array(0 => $sv));

  if ($rule_ident->length) {
    foreach ($rule_ident as $ident_node) {
      if (!in_array($ident_node->textContent, $references) && $ident_node->textContent != 'CCI') {
        $references[] = $ident_node->textContent;
      }
    }
  }

  if (count($references)) {
    foreach ($references as $key => $ref) {
      $tmp = null;
      if (substr($ref, 0, 3) == 'CVE' || substr($ref, 0, 3) == 'CAN') {
        $tmp[] = new cve($pdi_id, $ref);
        $db->save_CVE($tmp);
      }
      elseif (substr($ref, 0, 3) == 'CCE') {
        $tmp[] = new cce($pdi_id, $ref);
        $db->save_CCE($tmp);
      }
      elseif (substr($ref, 0, 2) == 'KB') {

      }
      elseif (substr($ref, 0, 2) == 'MS') {
        $tmp[] = new advisory($pdi_id, $ref, '', 'MS', '');
        $db->save_Advisory($tmp);
      }
      //print_r($tmp[0]);
      unset($tmp);
    }
  }

  if ($perc_comp % 100 == 0) {
    print "\t$perc_comp completed" . PHP_EOL;
  }

  // Output the CSV contents
  fputcsv($csv, [$rule_stig_id, $vms_id, implode("", array_fill(0, $cat, "I")), implode(" ", $ias), $rule_title, "Not Reviewed", "", $rule_check_content, $sv_rule, $oval_id]);

  unset($references);
  $db->update_Catalog_Script($base_name, ['name' => 'perc_comp', 'value' => ($perc_comp / $groups->length) * 100]);
}

$db->help->select_count("sagacity.stigs");
$stig_count = $db->help->execute();
$db->set_Setting('stig-count', $stig_count);

$end = new DateTime();
$diff = $end->diff($start);

print PHP_EOL . "Start Time: {$start->format("H:i:s")}" . PHP_EOL;
print "End Time: {$end->format("H:i:s")}" . PHP_EOL;
print "Execution time: {$diff->format("%H:%I:%S")}" . PHP_EOL . PHP_EOL;
print "New STIGs: $new_count" . PHP_EOL;
print "Updated STIGs: $updated_count" . PHP_EOL;
print "Total STIGs: " . ($new_count + $updated_count) . PHP_EOL . PHP_EOL . PHP_EOL;

$log->script_log("$groups->length complete");
fclose($csv);

if (!isset($cmd['debug'])) {
  rename($cmd['f'], DOC_ROOT . "/reference/stigs/$base_name");
}
rename($csv_file, DOC_ROOT . "/reference/stigs/" . basename($csv_file));
$db->update_Catalog_Script($base_name, ['name' => 'perc_comp', 'value' => 100, 'complete' => 1]);

/**
 * Usage output
 */
function usage() {
  print <<<EOO
Purpose: To parse a STIG XCCDF checklist file and populate/update the database

Usage: php parse_stig.php -f={STIG file} [--debug] [--ia_reset] [--draft] [--help]

 -f={STIG file}     The file to be parsed

 --debug            Debugging output
 --ia_reset         To delete any existing mapped IA controls and repopulate with what is in the checklist file
 --draft            This will allow the importing of a draft STIG file (normally excluded)
 --help             This screen

EOO;
}
