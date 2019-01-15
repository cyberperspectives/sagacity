<?php

/**
 * File: system.inc
 * Author: Ryan Prather
 * Purpose: Represents a system
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
 */

/**
 * Represents the different accredidation types
 *
 * @author Ryan Prather
 */
class accrediation_types {

  const DIACAP = 0;
  const RMF = 1;
  const PCI = 2;
  const NISPOM = 3;
  const HIPAA = 4;
  const SOX = 5;
  const COBIT = 6;

}

/**
 * Represent a the system being tested
 *
 * @author Ryan Prather
 */
class system {

  /**
   * System ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * System Name
   *
   * @var string
   */
  protected $name = '';

  /**
   * System name abbreviation
   *
   * @var string
   */
  protected $abbr = '';

  /**
   * System MAC level
   *
   * @var integer
   */
  protected $mac = 0;

  /**
   * System classification
   *
   * @var string
   */
  protected $classification = '';

  /**
   * System accrediation type
   *
   * @var accrediation_types
   */
  protected $accred_type = null;

  /**
   * System description
   *
   * @var string
   */
  protected $description = '';

  /**
   * System mitigations
   *
   * @var string
   */
  protected $mitigations = '';

  /**
   * System executive summary
   *
   * @var string
   */
  protected $executive_summary = '';

  /**
   * System diagram
   *
   * @var mixed
   */
  protected $diagram = null;

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param string $str_Name
   * @param integer $int_MAC
   * @param string $str_Class
   */
  public function __construct($int_ID, $str_Name, $int_MAC, $str_Class) {
    $this->id = $int_ID;
    $this->name = $str_Name;
    $this->mac = $int_MAC;
    $this->classification = $str_Class;
  }

  /**
   * Getter function for System Id
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Setter function for system ID
   *
   * @param integer $id_in
   */
  public function set_ID($id_in) {
    $this->id = $id_in;
  }

  /**
   * Getter function for system name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for system name
   *
   * @param string $str_Name
   */
  public function set_Name($str_Name) {
    $this->name = $str_Name;
  }

  /**
   * Getter function for system abbreviation
   *
   * @return string
   */
  public function get_Abbreviation() {
    return $this->abbr;
  }

  /**
   * Setter function for system abbreviation
   *
   * @param string $abbr_in
   */
  public function set_Abbreviation($abbr_in) {
    $this->abbr = $abbr_in;
  }

  /**
   * Getter function for MAC
   *
   * @return integer
   */
  public function get_MAC() {
    return $this->mac;
  }

  /**
   * Setter function for MAC
   *
   * @param integer $int_MAC
   */
  public function set_MAC($int_MAC) {
    $this->mac = $int_MAC;
  }

  /**
   * Getter function for classification
   *
   * @return string
   */
  public function get_Classification() {
    return $this->classification;
  }

  /**
   * Settr function for classification
   *
   * @param string $str_Class
   */
  public function set_Classification($str_Class) {
    $this->classification = $str_Class;
  }

  /**
   * Getter function for system accrediation type
   *
   * @return accrediation_types
   */
  public function get_Accreditation_Type() {
    return $this->accred_type;
  }

  /**
   * Setter function for system accrediation type
   *
   * @param accrediation_types $accred_type_in
   */
  public function set_Accreditation_Type($accred_type_in) {
    $this->accred_type = $accred_type_in;
  }

  /**
   * Getter function for system description
   *
   * @return string
   */
  public function get_Description() {
    return $this->description;
  }

  /**
   * Setter function for system description
   *
   * @param string $str_desc_in
   */
  public function set_Description($str_desc_in) {
    $this->description = $str_desc_in;
  }

  /**
   * Getter function for system mitigations
   *
   * @return string
   */
  public function get_Mitigations() {
    return $this->mitigations;
  }

  /**
   * Setter function for system mitigations
   *
   * @param string $str_mit_in
   */
  public function set_Mitigations($str_mit_in) {
    $this->mitigations = $str_mit_in;
  }

  /**
   * Getter function for system executive summary
   *
   * @return string
   */
  public function get_Executive_Summary() {
    return $this->executive_summary;
  }

  /**
   * Setter function for system executive summary
   *
   * @param string $exec_sum_in
   */
  public function set_Executive_Summary($exec_sum_in) {
    $this->executive_summary = $exec_sum_in;
  }

  /**
   * Getter function for system diagram
   *
   * @return mixed
   */
  public function get_Diagram() {
    return $this->diagram;
  }

  /**
   * Setter function for system diagram
   *
   * @param mixed $bin_diag_in
   */
  public function set_Diagram($bin_diag_in) {
    $this->diagram = $bin_diag_in;
  }

  /**
   * Getter function for preformated option tag
   *
   * @param boolean $selected_System
   * @param integer $ste_id
   * @return string
   */
  public function get_Option($selected_System = null, $ste_id = null) {
    return "<option value='" . $this->id . "" .
        (!is_null($ste_id) ? "_$ste_id'" : "'") .
        ($selected_System ? " selected" : "") .
        ">" . $this->name . "</option>";
  }

}
