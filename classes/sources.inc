<?php

/**
 * File: sources.inc
 * Author: Ryan Prather
 * Purpose: Represents a scan source
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
 *  - Sep 25, 2013 - added functions to access scan database items
 *  - Sep 1, 2016 - Updated Copyright and added functionality for an icon for the source
 */

/**
 * Represents a scan source
 *
 * @author Ryan Prather
 *
 */
class source {

  /**
   * Source Id
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Source name
   *
   * @var string
   */
  protected $name = '';

  /**
   * Source icon
   *
   * @var string
   */
  protected $icon = '';

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param string $str_Name
   */
  public function __construct($int_ID, $str_Name) {
    $this->id = $int_ID;
    $this->name = $str_Name;
  }

  /**
   * Getter function for source ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter function for source name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Settr function for source name
   *
   * @param string $str_Name
   */
  public function set_Name($str_Name) {
    $this->name = $str_Name;
  }

  /**
   * Getter function for source icon
   *
   * @return string
   */
  public function get_Icon() {
    return $this->icon;
  }

  /**
   * Setter function for source icon
   *
   * @param string $icon_in
   */
  public function set_Icon($icon_in) {
    $this->icon = $icon_in;
  }

}
