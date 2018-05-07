<?php

/**
 * File: sv_rule.inc
 * Author: Ryan Prather
 * Purpose: Represents a DISA SV_Rule which are STIG/Software dependent
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
 * Represents a DISA SV Rule
 *
 * @author Ryan Prather
 */
class sv_rule {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * SV Rule
   *
   * @var string
   */
  protected $sv_rule = '';

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_SV_Rule
   */
  public function __construct($int_PDI_ID, $str_SV_Rule) {
    $this->pdi_id = $int_PDI_ID;
    $this->sv_rule = $str_SV_Rule;
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
   * Getter function for SV Rule
   *
   * @return string
   */
  public function get_SV_Rule() {
    return $this->sv_rule;
  }

  /**
   * Setter function for SV Rule
   *
   * @param string $str_SV_Rule
   */
  public function set_SV_Rule($str_SV_Rule) {
    $this->sv_rule = $str_SV_Rule;
  }

}
