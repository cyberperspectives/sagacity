<?php

/**
 * File: proc_ia_controls.inc
 * Author: Ryan Prather
 * Purpose: Contain all classes that have to do with a procedural IA control
 * Created: Mar 17, 2014
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
 *  - Mar 17, 2014 - File created
 *  - Sep 1, 2016 - Updated Copyright and a couple comments
 */

/**
 * Procedural IA Controls
 *
 * @author Ryan Prather
 *
 */
class proc_ia_controls {

  /**
   * Array for status
   *
   * @var myltitype:string
   */
  private $STATUS = array(
    "Not Reviewed"   => 4,
    "Non-Compliant"  => 3,
    "Compliant"      => 2,
    "Not Applicable" => 1
  );

  /**
   * Reverses the status array
   *
   * @var multitype:integer
   */
  private $FLIPPED = array(
    4 => "Not Reviewed",
    3 => "Non-Compliant",
    2 => "Compliant",
    1 => "Not Applicable"
  );

  /**
   * Control ID
   *
   * @var string
   */
  protected $control_id = '';

  /**
   * Name
   *
   * @var string
   */
  protected $name = '';

  /**
   * Subject area
   *
   * @var string
   */
  protected $sub_area = '';

  /**
   * Description
   *
   * @var string
   */
  protected $desc = '';

  /**
   * Threat/vulnerability/countermeasures
   *
   * @var string
   */
  protected $tvcm = '';

  /**
   * General implementation guide
   *
   * @var string
   */
  protected $gimpg = '';

  /**
   * Resource guide
   *
   * @var string
   */
  protected $guide = '';

  /**
   * Impact
   *
   * @var string
   */
  protected $impact = '';

  /**
   * Array of sub ia controls
   *
   * @var multitype:proc_sub_ia_controls
   */
  protected $subs = array();

  /**
   * Control Finding
   *
   * @var control_finding
   */
  public $finding = null;

  /**
   * Constructor
   *
   * @param string $str_control_id_in
   * @param string $str_name_in
   * @param string $str_sub_area_in
   * @param string $str_desc_in
   * @param string $str_tvcm_in
   * @param string $str_gimpg_in
   * @param string $str_guide_in
   * @param string $str_impact_in
   */
  public function __construct($str_control_id_in, $str_name_in, $str_sub_area_in, $str_desc_in, $str_tvcm_in, $str_gimpg_in, $str_guide_in, $str_impact_in) {
    $this->control_id = $str_control_id_in;
    $this->desc = $str_desc_in;
    $this->name = $str_name_in;
    $this->sub_area = $str_sub_area_in;
    $this->tvcm = $str_tvcm_in;
    $this->gimpg = $str_gimpg_in;
    $this->guide = $str_guide_in;
    $this->impact = $str_impact_in;

    $this->finding = new control_finding();
  }

  /**
   * Function to get the status
   *
   * @param string|integer $val
   * @return multitype:integer|myltitype:string
   */
  public function get_Status($val) {
    if (is_numeric($val)) {
      return $this->FLIPPED[$val];
    }
    else {
      return $this->STATUS[$val];
    }
  }

  /**
   * Getter function for control ID
   *
   * @return string
   */
  public function get_Control_ID() {
    return $this->control_id;
  }

  /**
   * Setter function for control id
   *
   * @param string $str_control_id_in
   */
  public function set_Control_ID($str_control_id_in) {
    $this->control_id = $str_control_id_in;
  }

  /**
   * Getter function for name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for name
   *
   * @param string $str_name_in
   */
  public function set_Name($str_name_in) {
    $this->name = $str_name_in;
  }

  /**
   * Getter function for subject area
   *
   * @return string
   */
  public function get_Subject_Area() {
    return $this->sub_area;
  }

  /**
   * Setter function for subject area
   *
   * @param string $str_sub_area_in
   */
  public function set_Subject_Area($str_sub_area_in) {
    $this->sub_area = $str_sub_area_in;
  }

  /**
   * Getter function for description
   *
   * @return string
   */
  public function get_Description() {
    return $this->desc;
  }

  /**
   * Setter function for description
   *
   * @param string $str_desc_in
   */
  public function set_Description($str_desc_in) {
    $this->desc = $str_desc_in;
  }

  /**
   * Getter function for threat/vulnerability/countermeasures
   *
   * @return string
   */
  public function get_Threat_Vul_CM() {
    return $this->tvcm;
  }

  /**
   * Setter function for threat/vulnerability/countermeasures
   *
   * @param string $str_tvcm_in
   */
  public function set_Threat_Vul_CM($str_tvcm_in) {
    $this->tvcm = $str_tvcm_in;
  }

  /**
   * Getter function for implementation guide
   *
   * @return string
   */
  public function get_General_Implementation_Guide() {
    return $this->gimpg;
  }

  /**
   * Setter function for implementation guide
   *
   * @param string $str_gimpg_in
   */
  public function set_General_Implementation_Guide($str_gimpg_in) {
    $this->gimpg = $str_gimpg_in;
  }

  /**
   * Getter function for resource guide
   *
   * @return string
   */
  public function get_Resource_Guide() {
    return $this->guide;
  }

  /**
   * Setter function for resource guide
   *
   * @param string $str_guide_in
   */
  public function set_Resourse_Guide($str_guide_in) {
    $this->guide = $str_guide_in;
  }

  /**
   * Getter function for impact
   *
   * @return string
   */
  public function get_Impact() {
    return $this->impact;
  }

  /**
   * Setter function for impact
   *
   * @param string $str_impact_in
   */
  public function set_Impact($str_impact_in) {
    $this->impact = $str_impact_in;
  }

  /**
   * Getter function for sub controls
   *
   * @return multitype:proc_sub_ia_controls
   */
  public function get_Subs() {
    return $this->subs;
  }

  /**
   * Function to add new sub controls
   *
   * @param proc_sub_ia_controls $sub_in
   */
  public function add_Sub($sub_in) {
    $this->subs[] = $sub_in;
  }

  /**
   * Function to generate a display for procedural ops page
   *
   * @return string
   */
  public function get_Ops_Display($odd = true) {
    $status_count = array(
      'Not Reviewed'   => 0,
      'Non-Compliant'  => 0,
      'Compliant'      => 0,
      'Not Applicable' => 0
    );

    $current_status = 0;
    foreach ($this->subs as $key => $sub) {
      if ($this->STATUS[$sub->finding->status] > $current_status) {
        $current_status = $this->STATUS[$sub->finding->status];
      }
      $status_count[$sub->finding->status] ++;
    }

    $class = strtolower(str_replace(' ', '_', str_replace('-', '_', $this->FLIPPED[$current_status])));
    $parent_name = str_replace('-', '_', $this->control_id);
    $ret = "<tr>" .
        "<td class='cat_header' colspan='4'>" .
        "<span style='width:115px;cursor:pointer;' onclick=\"$('.$parent_name').toggle(300);\">" . $this->control_id . "</span>" .
        "<span style='width:310px;'>" . $this->name . "</span>" .
        "<span class='$class' id='$parent_name" . "_disp'>" . $this->FLIPPED[$current_status] . "</span>" .
        "<span class='override_status' id='" . $parent_name . "_or'>" .
        "Override: <input type='checkbox' onclick=\"$('#" . $parent_name . "_status').toggle();\" />" .
        "<select id='" . $parent_name . "_status' style='display:none;' onchange='field_id=\"$parent_name" . "_status\";update_status(\"$parent_name" . "_status\");'>" .
        "<option />" .
        "<option" . ($this->FLIPPED[$current_status] == 'Not Reviewed' ? ' selected' : '') . ">Not Reviewed</option>" .
        "<option" . ($this->FLIPPED[$current_status] == 'Non-Compliant' ? ' selected' : '') . ">Non-Compliant</option>" .
        "<option" . ($this->FLIPPED[$current_status] == 'Compliant' ? ' selected' : '') . ">Compliant</option>" .
        "<option" . ($this->FLIPPED[$current_status] == 'Not Applicable' ? ' selected' : '') . ">Not Applicable</option>" .
        "</select>" .
        "</span>" .
        "<span id='$parent_name" . "_Compliant' class='compliant' style='width:25px;text-align:center;'>" . $status_count['Compliant'] . "</span>" .
        "<span id='$parent_name" . "_Not_Reviewed' class='not_reviewed' style='width:25px;text-align:center;'>" . $status_count['Not Reviewed'] . "</span>" .
        "<span id='$parent_name" . "_Non_Compliant' class='non_compliant' style='width:25px;text-align:center;'>" . $status_count['Non-Compliant'] . "</span>" .
        "<span id='$parent_name" . "_Not_Applicable' class='not_applicable' style='width:25px;text-align:center;'>" . $status_count['Not Applicable'] . "</span>" .
        "</td>" .
        "</tr>" .
        "<tr class='" . ($odd ? 'odd' : 'even') . "_row $parent_name'>" .
        "<td style='width:117px;'>" . $this->control_id . "<br />" . $this->name . "</td>" .
        "<td style='width:150px;'>" . nl2br($this->desc) . "</td>" .
        "<td style='width:450px;'>" . nl2br($this->gimpg) . "</td>" .
        "<td>" .
        "Vulnerability Description:<br />" .
        "<textarea name='$parent_name" . "_vul_desc' id='$parent_name" . "_vul_desc'>" . $this->finding->vul_desc . "</textarea><br />" .
        "Mitigations:<br />" .
        "<textarea name='$parent_name" . "_mit' id='$parent_name" . "_mit'>" . $this->finding->mitigations . "</textarea><br />" .
        "References:<br />" .
        "<textarea name='$parent_name" . "_ref' id='$parent_name" . "_ref'>" . $this->finding->reference . "</textarea><br />" .
        "Notes:<br />" .
        "<textarea name='$parent_name" . "_notes' id='$parent_name" . "_notes'>" . $this->finding->notes . "</textarea>" .
        "</td>" .
        "</tr>";

    foreach ($this->subs as $key => $sub) {
      $odd = !$odd;
      $name = str_replace('-', '_', $sub->get_Sub_Control_ID());
      $ret .= "<tr class='" . ($odd ? 'odd' : 'even') . "_row $parent_name'>" .
          "<td style='width:117px;'>" . $sub->get_Sub_Control_ID() . "<br />" .
          "<input type='hidden' id='$name" . "_status_old' value='" . $sub->finding->status . "' />" .
          "<select name='$name" . "_status' id='$name" . "_status' style='width:95px;' onchange='field_id=\"$name" . "_status\";update_status();'>" .
          "<option" . ($sub->finding->status == 'Not Reviewed' ? ' selected' : '') . ">Not Reviewed</option>" .
          "<option" . ($sub->finding->status == 'Compliant' ? ' selected' : '') . ">Compliant</option>" .
          "<option" . ($sub->finding->status == 'Not Applicable' ? ' selected' : '') . ">Not Applicable</option>" .
          "<option" . ($sub->finding->status == 'Non-Compliant' ? ' selected' : '') . ">Non-Compliant</option>" .
          "</select>" .
          $sub->get_Name() . "</td>" .
          "<td style='width:150px;'>" . nl2br($sub->get_Objective()) . "</td>" .
          "<td style='width:450px;'>" . nl2br($sub->get_Script()) . "</td>" .
          "<td>" .
          "Test Result:<br />" .
          "<textarea name='$name" . "_test_result' id='$name" . "_test_result'>" . $sub->finding->test_result . "</textarea><br />" .
          "Mitigations:<br />" .
          "<textarea name='$name" . "_mit' id='$name" . "_mit'>" . $sub->finding->mitigation . "</textarea><br />" .
          "Milestones:<br />" .
          "<textarea name='$name" . "_milestone' id='$name" . "_milestone'>" . $sub->finding->milestone . "</textarea><br />" .
          "References:<br />" .
          "<textarea name='$name" . "_ref' id='$name" . "_ref'>" . $sub->finding->reference . "</textarea><br />" .
          "Notes:<br />" .
          "<textarea name='$name" . "_notes' id='$name" . "_notes'>" . $sub->finding->notes . "</textarea>" .
          "</td>" .
          "</tr>";
    }

    return $ret;
  }

  /**
   *
   * @return string
   */
  public function get_Worst_Status_String() {
    $current_status = 0;

    foreach ($this->subs as $key => $sub) {
      if ($this->STATUS[$sub->finding->status] > $current_status) {
        $current_status = $this->STATUS[$sub->finding->status];
        if ($current_status == $this->STATUS['Not Reviewed']) {
          break;
        }
      }
    }

    return $this->FLIPPED[$current_status];
  }

}

/**
 * Control Findings
 *
 * @author Ryan Prather
 */
class control_finding {

  /**
   * DB ID
   *
   * @var integer
   */
  public $id = 0;

  /**
   * Associated ST&E ID
   *
   * @var integer
   */
  public $ste_id = 0;

  /**
   * Control ID
   *
   * @var string
   */
  public $control_id = '';

  /**
   * Vulnerability description
   *
   * @var string
   */
  public $vul_desc = '';

  /**
   * Control mitigations
   *
   * @var string
   */
  public $mitigations = '';

  /**
   * Control references
   *
   * @var string
   */
  public $reference = '';
  public $risk_analysis = '';

  /**
   * Notes
   *
   * @var string
   */
  public $notes = '';

  /**
   * Tells the system that this control review is complete
   *
   * @var boolean
   */
  public $done = false;

}

/**
 * Procedural Sub IA Controls
 *
 * @author Ryan Prather
 *
 */
class proc_sub_ia_controls {

  /**
   * Sub control id
   *
   * @var string
   */
  protected $sub_control_id = '';

  /**
   * Name
   *
   * @var string
   */
  protected $name = '';

  /**
   * Objectives
   *
   * @var string
   */
  protected $objective = '';

  /**
   * Preparation
   *
   * @var string
   */
  protected $prep = '';

  /**
   * Script
   *
   * @var script
   */
  protected $script = '';

  /**
   * Expected Results
   *
   * @var string
   */
  protected $expected_results = '';

  /**
   * Procedural finding with notes
   *
   * @var proc_finding
   */
  public $finding = null;

  /**
   * Constructor
   *
   * @param string $str_sub_control_id_in
   * @param string $str_name_in
   * @param string $str_obj_in
   * @param string $str_prep_in
   * @param string $str_script_in
   * @param string $str_exp_results_in
   */
  public function __construct($str_sub_control_id_in, $str_name_in, $str_obj_in, $str_prep_in, $str_script_in, $str_exp_results_in) {
    $this->sub_control_id = $str_sub_control_id_in;
    $this->name = $str_name_in;
    $this->objective = $str_obj_in;
    $this->prep = $str_prep_in;
    $this->script = $str_script_in;
    $this->expected_results = $str_exp_results_in;
    $this->finding = new proc_finding();
  }

  /**
   * Getter function for sub control id
   *
   * @return string
   */
  public function get_Sub_Control_ID() {
    return $this->sub_control_id;
  }

  /**
   * Setter function for sub control id
   *
   * @param string $str_sub_control_id_in
   */
  public function set_Sub_Control_ID($str_sub_control_id_in) {
    $this->sub_control_id = $str_sub_control_id_in;
  }

  /**
   * Getter function for name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for name
   *
   * @param string $str_name_in
   */
  public function set_Name($str_name_in) {
    $this->name = $str_name_in;
  }

  /**
   * Getter function for objectives
   *
   * @return string
   */
  public function get_Objective() {
    return $this->objective;
  }

  /**
   * Setter function for objective
   *
   * @param string $str_obj_in
   */
  public function set_Objective($str_obj_in) {
    $this->objective = $str_obj_in;
  }

  /**
   * Getter function for preparations
   *
   * @return string
   */
  public function get_Preparation() {
    return $this->prep;
  }

  /**
   * Setter function fore preparations
   *
   * @param string $str_prep_in
   */
  public function set_Preparation($str_prep_in) {
    $this->prep = $str_prep_in;
  }

  /**
   * Getter function for script
   *
   * @return string
   */
  public function get_Script() {
    return $this->script;
  }

  /**
   * Setter function for script
   *
   * @param string $str_script_in
   */
  public function set_Script($str_script_in) {
    $this->script = $str_script_in;
  }

  /**
   * Getter function for expected results
   *
   * @return string
   */
  public function get_Expected_Results() {
    return $this->expected_results;
  }

  /**
   * Setter function for expected results
   *
   * @param string $str_exp_results_in
   */
  public function set_Expected_Results($str_exp_results_in) {
    $this->expected_results = $str_exp_results_in;
  }

}

/**
 * Procedural findings
 *
 * @author Ryan Prather
 *
 */
class proc_finding {

  /**
   * Finding ST&E ID
   *
   * @var integer
   */
  public $ste_id = 0;

  /**
   * Finding control id
   *
   * @var string
   */
  public $control_id = '';

  /**
   * Finding Status
   *
   * @var string
   */
  public $status = '';

  /**
   * Finding compliance statement
   *
   * @var string
   */
  public $test_result = '';

  /**
   * Finding mitigations
   *
   * @var string
   */
  public $mitigation = '';

  /**
   * Finding milestones
   *
   * @var string
   */
  public $milestone = '';

  /**
   * Finding reference
   *
   * @var string
   */
  public $reference = '';

  /**
   * Finding notes
   *
   * @var string
   */
  public $notes = '';

}
