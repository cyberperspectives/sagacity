<?php

/**
 * File: stigs.inc
 * Author: Ryan Prather
 * Purpose: Represents a DISA Security Technical Implementation Guide (STIG) item
 * Created: Sep 12, 2013
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 12, 2013 - File created
 */

/**
 * Represents a DISA STIG scan
 *
 * @author Ryan Prather
 *
 */
class stig {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * STIG ID
   *
   * @var string
   */
  protected $stig_id = '';

  /**
   * Description
   *
   * @var string
   */
  protected $description = '';

  /**
   * Tweak data function content
   *
   * @var string
   */
  protected $function = '';

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_STIG_ID
   * @param string $str_Description
   * @param string $str_Value
   */
  public function __construct($int_PDI_ID, $str_STIG_ID, $str_Description, $str_Value = null) {
    $this->pdi_id = $int_PDI_ID;
    $this->stig_id = $str_STIG_ID;
    $this->description = $str_Description;
  }

  /**
   * Getter function for PDI ID
   *
   * @return integer
   */
  public function get_PDI_ID() {
    return $this->pdi_id;
  }

  /**
   * Getter function for STIG ID
   *
   * @return string
   */
  public function get_ID() {
    return $this->stig_id;
  }

  /**
   * Setter function for STIG ID
   *
   * @param string $str_STIG_ID
   */
  public function set_ID($str_STIG_ID) {
    $this->stig_id = $str_STIG_ID;
  }

  /**
   * Getter function for description
   *
   * @return string
   */
  public function get_Description() {
    return $this->description;
  }

  /**
   * Setter function for description
   *
   * @param string $str_Description
   */
  public function set_Description($str_Description) {
    $this->description = $str_Description;
  }

  /**
   * Getter function for the tweak data function content
   *
   * @return string
   */
  public function get_Function() {
    return $this->function;
  }

  /**
   * Setter function for the tweak data function content
   *
   * @param string $str_Function_In
   */
  public function set_Function($str_Function_In) {
    $this->function = $str_Function_In;
  }

}
