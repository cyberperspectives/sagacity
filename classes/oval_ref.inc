<?php
/**
 * File: oval_ref.inc
 * Author: Ryan Prather
 * Purpose: Represents an oval reference
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
 * Represents an Oval Reference
 *
 * @author Ryan Prather
 *
 */
class oval_ref {
  /**
   * Oval ID
   *
   * @var string
   */
  protected $oval_id = '';

  /**
   * Source
   *
   * @var string
   */
  protected $source = '';

  /**
   * URL
   *
   * @var string
   */
  protected $url = '';

  /**
   * Reference ID
   *
   * @var string
   */
  protected $ref_id = '';

  /**
   * Constructor
   *
   * @param string $str_oval_id_in
   * @param string $str_source_in
   * @param string $str_url_in
   * @param string $str_ref_id_in
   */
  public function __construct($str_oval_id_in, $str_source_in, $str_url_in, $str_ref_id_in) {
    $this->oval_id = $str_oval_id_in;
    $this->source = $str_source_in;
    $this->url = $str_url_in;
    $this->ref_id = $str_ref_id_in;
  }

  /**
   * Get the oval id
   *
   * @return string
   */
  public function get_Oval_ID() {
    return $this->oval_id;
  }

  /**
   * Set the Oval ID
   *
   * @param string $str_oval_id_in
   */
  public function set_Oval_ID($str_oval_id_in) {
    $this->oval_id = $str_oval_id_in;
  }

  /**
   * Get the source
   *
   * @return string
   */
  public function get_Source() {
    return $this->source;
  }

  /**
   * Set the source
   *
   * @param string $str_source_in
   */
  public function set_Source($str_source_in) {
    $this->source = $str_source_in;
  }

  /**
   * Get the URL
   *
   * @return string
   */
  public function get_URL() {
    return $this->url;
  }

  /**
   * Set the URL
   *
   * @param string $str_url_in
   */
  public function set_URL($str_url_in) {
    $this->url = $str_url_in;
  }

  /**
   * Get the reference id
   *
   * @return string
   */
  public function get_Reference_ID() {
    return $this->ref_id;
  }

  /**
   * Set the reference id
   *
   * @param string $str_ref_id_in
   */
  public function set_Reference_ID($str_ref_id_in) {
    $this->ref_id = $str_ref_id_in;
  }
}