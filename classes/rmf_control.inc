<?php

/**
 * File: rmf_control.inc
 * Author: Ryan Prather
 * Purpose: Represent an NIST RMF IA control
 * Created: Jan 28, 2015
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
 *  - Jan 28, 2015 - File created
 *  - Sep 1, 2016 - Updated Copyright and added a few comments
 */

/**
 * Represent the RMF control family
 *
 * @author Ryan Prather
 */
class rmf_family {

  /**
   * Family abbreviation
   *
   * @var string
   */
  protected $abbr;

  /**
   * Family name
   *
   * @var string
   */
  protected $name;

  /**
   * Constructor
   */
  public function __construct() {

  }

  /**
   * Getter function for the family abbreviation
   *
   * @return string
   */
  public function get_Abbr() {
    return $this->abbr;
  }

  /**
   * Setter function for the family abbreviation
   *
   * @param string $abbr_in
   */
  public function set_Abbr($abbr_in) {
    $this->abbr = $abbr_in;
  }

  /**
   * Getter function for the family name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for the family name
   *
   * @param string $name_in
   */
  public function set_Name($name_in) {
    $this->name = $name_in;
  }

}

/**
 * Represent the RMF control itself
 *
 * @author Ryan Prather
 *
 */
class rmf_control {

  /**
   * Control family
   *
   * @var rmf_family
   */
  public $family;

  /**
   * Control id
   *
   * @var string
   */
  protected $control_id;

  /**
   * Control Name
   *
   * @var string
   */
  protected $name;

  /**
   * Control priority (0-3)
   *
   * @var int
   */
  protected $priority;

  /**
   * Control statement
   *
   * @var string
   */
  protected $statement;

  /**
   * Control supplemental guidance
   *
   * @var string
   */
  protected $guidance;

  /**
   * Which impact baseline this control applies to<br />
   *    When the object is created this will start out as an array with all elements being false
   *
   * @var array
   */
  protected $baseline;

  /**
   * Other RMF controls that relate to this one
   *
   * @var array:string
   */
  protected $related;

  /**
   * An array of enhancements to this control
   *
   * @var array:rmf_control_enhancements
   */
  protected $enh_controls;

  /**
   * Constructor
   */
  public function __construct() {
    $this->family = new rmf_family();
    $this->baseline = array("low" => false, "moderate" => false, "high" => false);
  }

  /**
   * Getter function for the control id
   *
   * @return string
   */
  public function get_Control_ID() {
    return $this->control_id;
  }

  /**
   * Setter function for the control id
   *
   * @param string $ctrl_id_in
   */
  public function set_Control_ID($ctrl_id_in) {
    $this->control_id = $ctrl_id_in;
  }

  /**
   * Getter function for the control name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for the control name
   *
   * @param string $name_in
   */
  public function set_Name($name_in) {
    $this->name = $name_in;
  }

  /**
   * Getter function for the control priority
   *
   * @return int
   */
  public function get_Priority() {
    return $this->priority;
  }

  /**
   * Setter function for the control priority
   *
   * @param int $pri_in
   */
  public function set_Priority($pri_in) {
    $this->priority = $pri_in;
  }

  /**
   * Getter function for the control statement
   *
   * @return string
   */
  public function get_Statement() {
    return $this->statement;
  }

  /**
   * Setter function for the control statement
   *
   * @param string $statement_in
   */
  public function set_Statement($statement_in) {
    $this->statement = $statement_in;
  }

  /**
   * Getter function for control guidance
   *
   * @return string
   */
  public function get_Guidance() {
    return $this->guidance;
  }

  /**
   * Setter function for the control guidance
   *
   * @param string $guidance_in
   */
  public function set_Guidance($guidance_in) {
    $this->guidance = $guidance_in;
  }

  /**
   * Function to set the usage for a particular baseline
   *
   * @param string $impact
   * @param boolean $setting
   */
  public function set_Baseline($impact, $setting) {
    if (in_array($impact, array("low", "moderate", "high"))) {
      $this->baseline[$impact] = $setting;
    }
  }

  /**
   * Function to return if a control is being used on a certain baseline
   *
   * @param string $impact
   *
   * @return boolean
   */
  public function get_Baseline($impact) {
    if (in_array($impact, array("low", "moderate", "high"))) {
      return $this->baseline[$impact];
    }

    return false;
  }

  /**
   * Function to get the worst baseline that is assigned to the control
   *
   * @return string|boolean
   */
  public function get_Worst_Baseline() {
    if ($this->baseline['high']) {
      return "high";
    }
    elseif ($this->baseline['moderate']) {
      return "moderate";
    }
    elseif ($this->baseline['low']) {
      return "low";
    }

    return false;
  }

  /**
   * Getter function for all the related controls
   *
   * @return array:string
   */
  public function get_Related_Controls() {
    return $this->related;
  }

  /**
   * Functio to add a control as a related control to this control
   *
   * @param string $ctrl_id_in
   */
  public function add_Related_Control($ctrl_id_in) {
    if (!in_array($ctrl_id_in, $this->related)) {
      $this->related[] = $ctrl_id_in;
    }
  }

  /**
   * Getter function to return all control enhancements
   *
   * @return array:rmf_control_enhancements
   */
  public function get_Enhanced_Controls() {
    return $this->enh_controls;
  }

  /**
   * Function to add a control enhancement
   *
   * @param rmf_control_enhancements $enh_in
   */
  public function add_Enhanced_Control($enh_in) {
    if (!in_array($enh_id, $this->enh_controls)) {
      $this->enh_controls[] = $enh_in;
    }
  }

}

/**
 * Represents any control enhancements
 *
 * @author Ryan Prather
 */
class rmf_control_enhancements {

  /**
   * Enhanced control ID
   *
   * @var string
   */
  protected $enh_id;

  /**
   * Enhanced control name
   *
   * @var string
   */
  protected $name;

  /**
   * Enhanced control statements
   *
   * @var string
   */
  protected $statement;

  /**
   * Enhanced control guidance
   *
   * @var string
   */
  protected $guidance;

  /**
   * Constructor
   */
  public function __construct() {

  }

  /**
   * Getter function for the enhanced control ID
   *
   * @return string
   */
  public function get_Enhanced_ID() {
    return $this->enh_id;
  }

  /**
   * Setter function for the enhanced control ID
   *
   * @param string $enh_id_in
   */
  public function set_Enhanced_ID($enh_id_in) {
    $this->enh_id = $enh_id_in;
  }

  /**
   * Getter function for the enhanced control name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for the enhanced control name
   *
   * @param string $name_in
   */
  public function set_Name($name_in) {
    $this->name = $name_in;
  }

  /**
   * Getter function for enhanced control statements
   *
   * @return string
   */
  public function get_Statement() {
    return $this->statement;
  }

  /**
   * Setter function for enhanced control statements
   *
   * @param string $statement_in
   */
  public function set_Statement($statement_in) {
    $this->statement = $statement_in;
  }

  /**
   * Getter function for enhanced control guidance
   *
   * @return string
   */
  public function get_Guidance() {
    return $this->guidance;
  }

  /**
   * Setter function for enhanced control guidance
   *
   * @param string $guidance_in
   */
  public function set_Guidance($guidance_in) {
    $this->guidance = $guidance_in;
  }

}
