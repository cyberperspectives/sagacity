<?php
/**
 * File: ia_control.inc
 * Author: Ryan Prather
 * Purpose: Represents an IA Control that can be applied to a PDI
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
 * Represents an IA Control that can be applied to a PDI
 *
 * @author Ryan Prather
 *
 */
class ia_control {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * Type
   *
   * @var string
   */
  protected $type = '';

  /**
   * Type ID
   *
   * @var integer
   */
  protected $type_id = 0;

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_Type
   * @param integer $int_Type_ID
   */
  public function __construct($int_PDI_ID, $str_Type, $int_Type_ID) {
    $this->pdi_id = $int_PDI_ID;
    $this->type = $str_Type;
    $this->type_id = $int_Type_ID;
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
   * Setter function for PDI ID
   *
   * @param integer $int_PDI_ID
   */
  public function set_PDI_ID($int_PDI_ID) {
    $this->pdi_id = $int_PDI_ID;
  }

  /**
   * Getter function for Type
   *
   * @return string
   */
  public function get_Type() {
    return $this->type;
  }

  /**
   * Setter function for type
   *
   * @param string $str_Type
   */
  public function set_Type($str_Type) {
    $this->type = $str_Type;
  }

  /**
   * Getter function for type ID
   *
   * @return integer
   */
  public function get_Type_ID() {
    return $this->type_id;
  }

  /**
   * Setter function for type ID
   *
   * @param integer $int_Type_ID
   */
  public function set_Type_ID($int_Type_ID) {
    $this->type_id = $int_Type_ID;
  }

  /**
   * Function to print a IA Control in the proper format
   *
   * @return string
   */
  public function print_Control() {
    if($this->type == 'CCI') {
      return $this->type."-".str_pad($this->type_id, 6, "0", STR_PAD_LEFT);
    }

    return $this->type."-".$this->type_id;
  }

}