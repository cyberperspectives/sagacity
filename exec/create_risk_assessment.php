<?php

/**
 * File: create_risk_assessment.php
 * Author: Ryan Prather
 * Purpose: File to create a final risk assessment output file
 * Created: Oct 20, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Oct 20, 2014 - File created
 */
$cmd = getopt("s:", array("debug::"));

if (isset($cmd['debug'])) {
  $path = realpath("/Users/pratherr/workspace/web/exec");
}
else {
  $path = realpath("/xampp/www/exec");
}

chdir($path);

set_time_limit(0);
set_include_path(get_include_path());

include_once 'database.inc';
include_once 'helper.inc';

$db = new db();
$log = new Sagacity_Error("Create_Risk_Assessment.log");

$ste = $db->get_STE($cmd['s'])[0];
$sys = $db->get_System_By_STE_ID($cmd['s']);
$site = $db->get_Site_By_STE_ID($cmd['s']);
$tgts = $db->get_Target_Details($cmd['s']);

$xml = new DOMDocument();
$pi = $xml->createProcessingInstruction("xml-stylesheet", 'type="text/xsl" href="diacap.xsl"');
$xml->appendChild($pi);

$xml->appendChild($report = xml_helper($xml, 'report'));
$report->appendChild($ste_node = xml_helper($xml, "ste", null, false, array(
  'start_date'           => $ste->get_Eval_Start_Date()->format("Y-m-d"),
  'end_date'             => $ste->get_Eval_End_Date()->format("Y-m-d"),
  'status'               => $ste->get_Status(),
  'ao'                   => $ste->get_AO(),
  'proc_checklist_fname' => "Procedural-eChecklist-" . $ste->get_ID() . ".xlsx"
)));
$ste_node->appendChild(xml_helper($xml, "recommendations", $ste->get_Recommendations(), true));
$ste_node->appendChild(xml_helper($xml, "conclusion", $ste->get_Conclusions(), true));
$ste_node->appendChild(xml_helper($xml, "constraints", $ste->get_Constraints(), true));
$ste_node->appendChild(xml_helper($xml, "assumptions", $ste->get_Assumptions(), true));
$ste_node->appendChild(xml_helper($xml, "residual_risk", $ste->get_Residual_Risk(), true));
$ste_node->appendChild(xml_helper($xml, "deviations", $ste->get_Deviations(), true));
$ste_node->appendChild(xml_helper($xml, "scope", $ste->get_Scope(), true));

$ste_node->appendChild($team = xml_helper($xml, "ste_team"));
foreach ($ste->get_STE_Team() as $key => $people) {
  $team->appendChild(xml_helper($xml, "member", null, false, array(
    'name'     => $people->name,
    'org'      => $people->org,
    'phone'    => $people->phone,
    'position' => $people->position
  )));
}

$report->appendChild($sys_node = xml_helper($xml, "system", null, false, array(
  'name'  => $sys->get_Name(),
  'class' => $sys->get_Classification(),
  'mac'   => $sys->get_MAC()
)));
$sys_node->appendChild(xml_helper($xml, "description", $sys->get_Description(), true));
$sys_node->appendChild(xml_helper($xml, "executive_summary", $sys->get(), true));

$report->appendchild(xml_helper($xml, "site", null, false, array(
  'name'      => $site->get_Name(),
  'address'   => $site->get_Address(),
  'city'      => $site->get_City(),
  'state'     => $site->get_State(),
  'zip'       => $site->get_Zip(),
  'country'   => $site->get_Country(),
  'poc_name'  => $site->get_POC_Name(),
  'poc_email' => $site->get_POC_Email(),
  'poc_phone' => $site->get_POC_Phone()
)));

$report->appendChild($targets = xml_helper($xml, "targets"));

foreach ($tgts as $key => $tgt) {
  $os = $db->get_Software($tgt->get_OS_ID())[0];
  $targets->appendChild($tgt_node = xml_helper($xml, "target", null, false, array(
    'name' => $tgt->get_Name(),
    'os'   => $os->get_Man() . " " . $os->get_Name() . " " . $os->get_Version()
  )));

  foreach ($tgt->interfaces as $key => $int) {
    if (false) {
      $int = new interfaces();
    }
    $tgt_node->appendChild(xml_helper($xml, "interface", null, false, array(
      'name'     => $int->get_Name(),
      'hostname' => $int->get_Hostname(),
      'ipv4'     => $int->get_IPv4(),
      'ipv6'     => $int->get_IPv6(),
      'fqdn'     => $int->get_FQDN()
    )));
  }
}

$report->appendChild($ia_node = xml_helper($xml, "ia_controls"));

$proc = $db->get_Proc_IA_Controls($ste);
foreach ($proc as $key => $ia) {
  $ia_node->appendChild($node = xml_helper($xml, "ia_control", null, false, array(
    'id'     => $ia->get_Control_ID(),
    'name'   => $ia->get_Name(),
    'status' => $ia->get_Worst_Status_String()
  )));

  $node->appendChild(xml_helper($xml, "vuln_desc", $ia->finding->vul_desc, true));
  $node->appendChild(xml_helper($xml, "mitigations", $ia->finding->mitigations, true));
  $node->appendChild(xml_helper($xml, "references", $ia->finding->reference, true));
  $node->appendChild(xml_helper($xml, "notes", $ia->finding->notes, true));
}

$xml->formatOutput = true;
$xml->save("../report/" . $sys->get_Name() . "_" . $site->get_Name() . "_" . $ste->get_Eval_Start_Date()->format("Y_m_d") . ".xml");
