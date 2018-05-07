<?php
/**
 * File: oval.inc
 * Author: Ryan Prather
 * Purpose: Represents an Oval check
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

include_once 'oval_ref.inc';

/**
 * Represents an Oval check
 *
 * @author Ryan Prather
 *
 */
class oval {
  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * Oval ID
   *
   * @var string
   */
  protected $oval_id = '';

  /**
   * Definition title
   *
   * @var string
   */
  protected $title = '';

  /**
   * Definition description
   *
   * @var string
   */
  protected $desc = '';

  /**
   * Platform
   *
   * @var string
   */
  protected $platform = '';

  /**
   * External definition
   *
   * @var string
   */
  protected $ext_def = '';

  /**
   * External definition operator
   *
   * @var string
   */
  protected $ext_def_op = '';

  /**
   * Array of oval references
   *
   * @var multitype:oval_ref
   */
  protected $oval_ref = array();

  /**
   * Constructor
   *
   * @param integer $int_pdi_id_in
   * @param string $str_oval_id_in
   * @param string $str_title_in
   * @param string $str_desc_in
   * @param string $str_platform_in
   * @param string $str_ext_def_in
   * @param string $str_ext_def_op_in
   */
  public function __construct($int_pdi_id_in, $str_oval_id_in, $str_title_in, $str_desc_in,
                              $str_platform_in, $str_ext_def_in, $str_ext_def_op_in) {
    $this->pdi_id = $int_pdi_id_in;
    $this->oval_id = $str_oval_id_in;
    $this->title = $str_title_in;
    $this->desc = $str_desc_in;
    $this->platform = $str_platform_in;
    $this->ext_def = $str_ext_def_in;
    $this->ext_def_op = $str_ext_def_op_in;
  }

  /**
   * Get pdi id
   *
   * @return integer
   */
  public function get_PDI_ID() {
    return $this->pdi_id;
  }

  /**
   * Set pdi id
   *
   * @param integer $int_pdi_id_in
   */
  public function set_PDI_ID($int_pdi_id_in) {
    $this->pdi_id = $int_pdi_id_in;
  }

  /**
   * Get oval id
   *
   * @return string
   */
  public function get_Oval_ID() {
    return $this->oval_id;
  }

  /**
   * Set oval id
   *
   * @param string $str_oval_id_in
   */
  public function set_Oval_ID($str_oval_id_in) {
    $this->oval_id = $str_oval_id_in;
  }

  /**
   * Get definition title
   *
   * @return string
   */
  public function get_Title() {
    return $this->title;
  }

  /**
   * Set definition title
   *
   * @param string $str_title_in
   */
  public function set_Title($str_title_in) {
    $this->title = $str_title_in;
  }

  /**
   * Get the definition description
   *
   * @return string
   */
  public function get_Description() {
    return $this->desc;
  }

  /**
   * Set the definition description
   *
   * @param string $str_desc_in
   */
  public function set_Description($str_desc_in) {
    $this->desc = $str_desc_in;
  }

  /**
   * Get the platform that is affected by this definition
   *
   * @return string
   */
  public function get_Platform() {
    return $this->platform;
  }

  /**
   * Set the platform that is affected by this definition
   *
   * @param string $str_platform_in
   */
  public function set_Platform( $str_platform_in) {
    $this->platform = $str_platform_in;
  }

  /**
   * Get the external definition
   *
   * @return string
   */
  public function get_External_Definition() {
    return $this->ext_def;
  }

  /**
   * Set the external definition
   *
   * @param string $str_ext_def_in
   */
  public function set_External_Definition($str_ext_def_in) {
    $this->ext_def = $str_ext_def_in;
  }

  /**
   * Get the external definition operator
   *
   * @return string
   */
  public function get_External_Definition_Operator() {
    return $this->ext_def_op;
  }

  /**
   * Set the external definition operator
   *
   * @param string $str_ext_def_op_in
   */
  public function set_External_Definition_Operator($str_ext_def_op_in) {
    $this->ext_def_op = $str_ext_def_op_in;
  }

  /**
   * Return the array of Oval References
   *
   * @return multitype:oval_ref
   */
  public function get_References() {
    return $this->oval_ref;
  }

  /**
   * Add a reference to the oval_ref variable
   *
   * @param oval_ref $oval_ref_in
   */
  public function add_Reference($oval_ref_in) {
    $this->oval_ref[] = $oval_ref_in;
  }

  /**
   * Function to clear the oval reference array
   */
  public function clear_References() {
    $this->oval_ref = array();
  }
}