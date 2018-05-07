<?php

/**
 * File: script.inc
 * Author: Ryan Prather
 * Purpose: To instantiate a script object that can run on the system
 * Created: Sep 27, 2013
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
 *  - Sep 27, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright and removed result_script and script_type classes due to merger with scan class
 */

/**
 *
 * @author Ryan Prather
 *
 */
class script {

  /**
   * ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Script name
   *
   * @var string
   */
  protected $name = '';

  /**
   * Script file name
   *
   * @var string
   */
  protected $file_name = '';

  /**
   * Script arguments
   *
   * @var array:string
   */
  protected $args = array();

  /**
   * Last update
   *
   * @var DateTime
   */
  protected $updated;

  /**
   * Script path
   *
   * @var string
   */
  protected $path = '';

  /**
   * Script version
   *
   * @var string
   */
  protected $version = '';

  /**
   * Call back function
   *
   * @var string
   */
  protected $function = '';

  /**
   * Script type
   *
   * @var string
   */
  protected $type = '';

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param string $str_Name
   * @param string $str_File_Name
   * @param string $str_Args
   * @param string $dt_Updated
   * @param string $str_Path
   * @param string $str_Version
   * @param string $str_Function
   * @param string $str_Type
   */
  public function __construct($int_ID, $str_Name, $str_File_Name, $str_Args, $dt_Updated, $str_Path, $str_Version, $str_Function, $str_Type) {
    $this->id = $int_ID;
    $this->name = $str_Name;
    $this->file_name = $str_File_Name;
    $this->args = unserialize($str_Args);
    $this->updated = new DateTime($dt_Updated);
    $this->path = $str_Path;
    $this->version = $str_Version;
    $this->function = $str_Function;
    $this->type = $str_Type;
  }

  /**
   * Getter function for ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter function for name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Getter function for file name
   *
   * @return string
   */
  public function get_File_Name() {
    return $this->file_name;
  }

  /**
   * Getter function for script arguments
   *
   * @return multitype:string
   */
  public function get_Args() {
    return $this->args;
  }

  /**
   * Getter function for update
   *
   * @return DateTime
   */
  public function get_Update() {
    return $this->updated;
  }

  /**
   * Getter function for path
   *
   * @return string
   */
  public function get_Path() {
    return $this->path;
  }

  /**
   * Getter function for script version
   *
   * @return string
   */
  public function get_Version() {
    return $this->version;
  }

  /**
   * Getter function for callback function
   *
   * @return string
   */
  public function get_Function() {
    return $this->function;
  }

  /**
   * Getter function for script type
   *
   * @return string
   */
  public function get_Type() {
    return $this->type;
  }

  /**
   * Getter function for preformated &lt;option&gt; tag
   *
   * @param boolean $selected_script
   * @return string
   */
  public function get_Option($selected_script = null) {
    return "<option value='$this->id' " . ($selected_script == $this->id ? 'selected' : '') .
        ">$this->name</option>";
  }

}

/**
 * Class to define a catalog parsing script
 *
 * @author Ryan Prather
 */
class catalog_script {

  /**
   * The file name that the script is parsing
   *
   * @var string
   */
  public $file_name = '';

  /**
   * The process ID of the script that is running
   *
   * @var integer
   */
  public $pid = 0;

  /**
   * The time the script started
   *
   * @var string
   */
  public $start_time = '';

  /**
   * The time the script was last updated
   *
   * @var string
   */
  public $last_update = '';

  /**
   * The status of the script
   *
   * @var integer
   */
  public $status = 0;

  /**
   * The percentage that the script has completed
   *
   * @var float
   */
  public $perc_comp = 0.0;

  /**
   * The number of STIGs in the catalog file
   *
   * @var integer
   */
  public $stig_count = 0;

  /**
   * Constructor
   */
  public function __construct() {

  }

}
