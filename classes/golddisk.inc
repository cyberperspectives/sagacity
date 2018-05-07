<?php
/**
 * File: golddisk.inc
 * Author: Ryan Prather
 * Purpose: Represents a Golddisk check
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
 * Represent a Golddisk check
 *
 * @author Ryan Prather
 *
 */
class golddisk {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * VMS ID
   *
   * @var string
   */
  protected $vms_id = '';

  /**
   * Short Title
   *
   * @var string
   */
  protected $short_title = '';

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_VMS_ID
   * @param string $str_Short_Title
   */
  public function __construct($int_PDI_ID, $str_VMS_ID, $str_Short_Title) {
    $this->pdi_id = $int_PDI_ID;
    $this->vms_id = $str_VMS_ID;
    $this->short_title = $str_Short_Title;
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
   * Getter function for VMS ID
   *
   * @return string
   */
  public function get_ID() {
    return $this->vms_id;
  }

  /**
   * Setter function for VMS ID
   *
   * @param string $str_VMS_ID
   */
  public function set_ID($str_VMS_ID) {
    $this->vms_id = $str_VMS_ID;
  }

  /**
   * Getter function for short title
   *
   * @return string
   */
  public function get_Short_Title() {
    return $this->short_title;
  }

  /**
   * Setter function for short title
   *
   * @param string $str_Short_Title
   */
  public function set_Short_Title($str_Short_Title) {
    $this->short_title = $str_Short_Title;
  }

}