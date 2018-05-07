<?php
/**
 * File: advisories.inc
 * Author: Ryan Prather
 * Purpose: This class creates an advisory from the software vendor.
 * 			This advisory can be used to link other PDIs
 * Created: Sep 16, 2013
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 16, 2013 - File created
 */

/**
 *
 * @author Ryan Prather
 *
 */
class advisory {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * Advisory ID
   *
   * @var string
   */
  protected $adv_id = '';

  /**
   * Reference text for the advisory
   *
   * @var string
   */
  protected $reference = '';

  /**
   * Type of the advisory (MS, KB, RH, etc)
   *
   * @var string
   */
  protected $type = '';

  /**
   * URL to issuing vendor
   *
   * @var string
   */
  protected $url = '';

  /**
   * Advisory title
   *
   * @var string
   */
  protected $title = '';

  /**
   * Advisory impact
   *
   * @var string
   */
  protected $impact = '';

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_Advisory
   * @param string $str_Ref
   * @param string $str_Type
   * @param string $str_URL
   */
  public function __construct($int_PDI_ID, $str_Advisory, $str_Ref, $str_Type, $str_URL) {
    $this->pdi_id = $int_PDI_ID;
    $this->adv_id = $str_Advisory;
    $this->reference = $str_Ref;
    $this->type = $str_Type;
    $this->url = $str_URL;
  }

  /**
   * Getter function for the advisory PDI linkage
   *
   * @return integer
   */
  public function get_PDI_ID() {
    return $this->pdi_id;
  }

  /**
   * Setter function for the advisory PDI linkage
   *
   * @param integer $int_PDI_ID
   */
  public function set_PDI_ID($int_PDI_ID) {
    $this->pdi_id = $int_PDI_ID;
  }

  /**
   * Getter function for advisory ID
   *
   * @return string
   */
  public function get_Advisory_ID() {
    return $this->adv_id;
  }

  /**
   * Setter function for advisory ID
   *
   * @param string $str_Advisory_ID
   */
  public function set_Advisory_ID($str_Advisory_ID) {
    $this->adv_id = $str_Advisory_ID;
  }

  /**
   * Getter function for the advisory reference text
   *
   * @return string
   */
  public function get_Ref_Text() {
    return $this->reference;
  }

  /**
   * Setter function for the advisory reference text
   *
   * @param string $str_Ref
   */
  public function set_Ref_Text($str_Ref) {
    $this->reference = $str_Ref;
  }

  /**
   * Getter function for the advisory type
   *
   * @return string
   */
  public function get_Type() {
    return $this->type;
  }

  /**
   * Setter function for the advisory type
   *
   * @param string $str_Type
   */
  public function set_Type($str_Type) {
    $this->type = $str_Type;
  }

  /**
   * Getter function for the advisory URL
   *
   * @return string
   */
  public function get_URL() {
    return $this->url;
  }

  /**
   * Setter for the advisory URL
   *
   * @param string $str_URL
   */
  public function set_URL($str_URL) {
    $this->url = $str_URL;
  }

  /**
   * Getter function for advisory title
   *
   * @return string
   */
  public function get_Title() {
    return $this->title;
  }

  /**
   * Setter function for advisory title
   *
   * @param string $str_Title_In
   */
  public function set_Title($str_Title_In) {
    $this->title = $str_Title_In;
  }

  /**
   * Getter function for advisory impact
   *
   * @return string
   */
  public function get_Impact() {
    return $this->impact;
  }

  /**
   * Setter function for advisory impact
   *
   * @param string $str_Impact_In
   */
  public function set_Impact($str_Impact_In) {
    $this->impact = $str_Impact_In;
  }
}