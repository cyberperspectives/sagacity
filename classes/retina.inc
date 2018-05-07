<?php
/**
 * File: retina.inc
 * Author: Ryan Prather
 * Purpose: Represents a Retina scan
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
 * Represents a Retina scan
 *
 * @author Ryan Prather
 *
 */
class retina {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * Retina ID
   *
   * @var string
   */
  protected $retina_id = '';

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_Retina_ID
   */
  public function __construct($int_PDI_ID, $str_Retina_ID) {
    $this->pdi_id = $int_PDI_ID;
    $this->retina_id = $str_Retina_ID;
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
   * Getter function for Retina ID
   *
   * @return string
   */
  public function get_Retina_ID() {
    return $this->retina_id;
  }

  /**
   * Setter function for Retina ID
   *
   * @param string $str_Retina_ID
   */
  public function set_Retina_ID($str_Retina_ID) {
    $this->retina_id = $str_Retina_ID;
  }

}