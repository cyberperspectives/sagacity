<?php

/**
 * File: ste.inc
 * Author: Ryan Prather
 * Purpose: Represents an ST&E
 * Created: Sep 12, 2013
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
 *  - Sep 12, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright and added comments
 *  - Jan 10, 2018 - Changed $site and $system to class objects instead of ID's
 */
include_once 'people.inc';

/**
 * Represents the ST&E itself
 *
 * @author Ryan Prather
 */
class ste {

  /**
   * STE ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * System ID
   *
   * @var site
   */
  protected $system = 0;

  /**
   * Site ID
   *
   * @var site
   */
  protected $site = 0;

  /**
   * Evaluation start date
   *
   * @var DateTime
   */
  protected $eval_start;

  /**
   * Evaluation end date
   *
   * @var DateTime
   */
  protected $eval_end;

  /**
   * Does this ST&amp;E contain multiple systems
   *
   * @var boolean
   */
  protected $multiple = false;

  /**
   * What is the primary ST&amp;E
   *
   * @var integer
   */
  protected $primary = 0;

  /**
   * What is the scope of the ST&amp;E
   *
   * @var string
   */
  protected $scope = '';

  /**
   * ST&amp;E Assumptions
   *
   * @var string
   */
  protected $assumptions = '';

  /**
   * ST&amp;E Constraints
   *
   * @var string
   */
  protected $constraints = '';

  /**
   * ST&amp;E Recommendations
   *
   * @var string
   */
  protected $recommendations = '';

  /**
   * Residual risk
   *
   * @var string
   */
  protected $residual_risk = '';

  /**
   * Deviations from the ST&amp;E plan
   *
   * @var string
   */
  protected $deviations = '';

  /**
   * Final conclusions of the ST&amp;E
   *
   * @var string
   */
  protected $conclusions = '';

  /**
   * Final status of the system
   *
   * @var string
   */
  protected $status = '';

  /**
   * Individual approving official
   *
   * @var string
   */
  protected $ao = '';

  /**
   * Members of the ST&E team
   *
   * @var array:people
   */
  protected $ste_team = array();

  /**
   *
   * @param integer $id
   * @param system $system
   * @param site $site
   * @param string $eval_Start
   * @param string $eval_End
   * @param boolean $multiple_in
   * @param integer $primary_in
   */
  public function __construct($id, $system, $site, $eval_Start, $eval_End, $multiple_in, $primary_in) {
    $this->id = $id;
    $this->system = $system;
    $this->site = $site;
    $this->eval_end = new DateTime($eval_End);
    $this->eval_start = new DateTime($eval_Start);
    $this->multiple = $multiple_in;
    $this->primary = $primary_in;
  }

  /**
   * Getter function for STE ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Setter function for STE ID
   *
   * @param integer $id_in
   */
  public function set_ID($id_in) {
    $this->id = $id_in;
  }

  /**
   * Getter function for System Id
   *
   * @return integer
   */
  public function get_System() {
    return $this->system;
  }

  /**
   * Getter function for Site ID
   *
   * @return integer
   */
  public function get_Site() {
    return $this->site;
  }

  /**
   * Getter function for evaluation start date
   *
   * @return DateTime
   */
  public function get_Eval_Start_Date() {
    return $this->eval_start;
  }

  /**
   * Getter function for evaluation end date
   *
   * @return DateTime
   */
  public function get_Eval_End_Date() {
    return $this->eval_end;
  }

  /**
   * Does this ST&E have multiple systems
   *
   * @return boolean
   */
  public function is_Multiple() {
    return $this->multiple;
  }

  /**
   * Getter function for primary ID
   *
   * @return integer
   */
  public function get_Primary_ID() {
    return $this->primary;
  }

  /**
   * Setter function for primary ID
   *
   * @param integer $primary_in
   */
  public function set_Primary_ID($primary_in) {
    $this->primary = $primary_in;
  }

  /**
   * Getter function for ST&amp;E Scope
   *
   * @return string
   */
  public function get_Scope() {
    return $this->scope;
  }

  /**
   * Setter function for ST&amp;E Scope
   *
   * @param string $scope_in
   */
  public function set_Scope($scope_in) {
    $this->scope = $scope_in;
  }

  /**
   * Getter function for ST&amp;E Assumptions
   *
   * @return string
   */
  public function get_Assumptions() {
    return $this->assumptions;
  }

  /**
   * Setter function for ST&amp;E Assumptions
   *
   * @param string $assumptions_in
   */
  public function set_Assumptions($assumptions_in) {
    $this->assumptions = $assumptions_in;
  }

  /**
   * Getter function for ST&amp;E Constraints
   *
   * @return string
   */
  public function get_Constraints() {
    return $this->constraints;
  }

  /**
   * Setter function for ST&amp;E Constraints
   *
   * @param string $constraints_in
   */
  public function set_Constraints($constraints_in) {
    $this->constraints = $constraints_in;
  }

  /**
   * Getter function for ST&amp;E Deviations
   *
   * @return string
   */
  public function get_Deviations() {
    return $this->deviations;
  }

  /**
   * Setter function for ST&amp;E Deviations
   *
   * @param string $deviation_in
   */
  public function set_Deviations($deviation_in) {
    $this->deviations = $deviation_in;
  }

  /**
   * Getter functions for ST&amp;E Recommendations
   *
   * @return string
   */
  public function get_Recommendations() {
    return $this->recommendations;
  }

  /**
   * Setter function for ST&amp;E Recommendations
   *
   * @param string $recommendations_in
   */
  public function set_Recommendations($recommendations_in) {
    $this->recommendations = $recommendations_in;
  }

  /**
   * Getter function for ST&amp;E Residual Risk
   *
   * @return string
   */
  public function get_Residual_Risk() {
    return $this->residual_risk;
  }

  /**
   * Setter function for ST&amp;E Residual Risk
   *
   * @param string $residual_risk_in
   */
  public function set_Residual_Risk($residual_risk_in) {
    $this->residual_risk = $residual_risk_in;
  }

  /**
   * Getter function for ST&amp;E Conclusions
   *
   * @return string
   */
  public function get_Conclusions() {
    return $this->conclusions;
  }

  /**
   * Setter function for ST&amp;E Conclusions
   *
   * @param string $conclusions_in
   */
  public function set_Conclusions($conclusions_in) {
    $this->conclusions = $conclusions_in;
  }

  /**
   * Getter function for the ST&amp;E status
   *
   * @return string
   */
  public function get_Status() {
    return $this->status;
  }

  /**
   * Setter function for the ST&amp;E status
   *
   * @param string $str_status
   */
  public function set_Status($str_status) {
    $this->status = $str_status;
  }

  /**
   * Getter function for the approving official
   *
   * @return string
   */
  public function get_AO() {
    return $this->ao;
  }

  /**
   * Setter function for the approving official
   *
   * @param string $str_ao
   */
  public function set_AO($str_ao) {
    $this->ao = $str_ao;
  }

  /**
   * Getter function for the ST&amp;E team members
   *
   * @return array:people
   */
  public function get_STE_Team() {
    return $this->ste_team;
  }

  /**
   * Function to add team members to the ST&amp;E
   *
   * @param people $people
   */
  public function add_STE_Team_Member($people) {
    $this->ste_team[] = $people;
  }

}
