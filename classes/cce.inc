<?php
/**
 * File: cce.inc
 * Author: Ryan Prather
 * Purpose: Represents a CCE
 * Created: Sep 26, 2013
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 26, 2013 - File created
 */

/**
 * Represents a CCE
 *
 * @author Ryan Prather
 *
 */
class cce {
  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * CCE ID
   *
   * @var string
   */
  protected $cce_id = '';

  /**
   * Constructor
   *
   * @param integer $pdi_id_in
   *    PDI ID that this is linked to
   * @param string $cce_in
   *    CCE ID
   */
  public function __construct($pdi_id_in, $cce_in) {
    $this->pdi_id = $pdi_id_in;
    $this->cce_id = $cce_in;
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
   * Getter function for CCE
   *
   * @return string
   */
  public function get_CCE_ID() {
    return $this->cce_id;
  }
}