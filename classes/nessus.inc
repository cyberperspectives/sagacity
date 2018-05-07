<?php

/**
 * File: nessus.inc
 * Author: Ryan Prather
 * Purpose: Represents a Nessus scan
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
 *  - Mar 22, 2017 - Removed setting function for values that were moved to meta data,
 *                   Added compare_Reference function to compare 2 references from 2 nessus objects
 */

/**
 * Represents a Nessus scan
 *
 * @author Ryan Prather
 *
 */
class nessus {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * Nessus Id
   *
   * @var string
   */
  protected $nessus_id = '';

  /**
   * Name
   *
   * @var string
   */
  protected $name = '';

  /**
   * Summary
   *
   * @var string
   */
  protected $summary = '';

  /**
   * Description
   *
   * @var string
   */
  protected $description = '';

  /**
   * Solution
   *
   * @var string
   */
  protected $solution = '';

  /**
   * Family
   *
   * @var unknown
   */
  protected $family = '';

  /**
   * Category
   *
   * @var string
   */
  protected $category = '';

  /**
   * Copyright
   *
   * @var string
   */
  protected $copyright = '';

  /**
   * Protocol
   *
   * @var string
   */
  protected $protocol = '';

  /**
   * Version of the plugin
   *
   * @var string
   */
  protected $version = '';

  /**
   * File name of the Nessus plugin file
   *
   * @var string
   */
  protected $file_name = '';

  /**
   * Date of the Nessus plugin file
   *
   * @var string
   */
  protected $file_date = '';

  /**
   * Array of reference IDs that link to this plugin
   *   multidimensional array, first dimension is type, second dimension is value
   *
   * @var array
   */
  protected $refs = array();

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_Nessus_ID
   */
  public function __construct($int_PDI_ID, $str_Nessus_ID) {
    $this->pdi_id = $int_PDI_ID;
    $this->nessus_id = $str_Nessus_ID;

    $this->refs = array();
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
   * Getter function for Nessus ID
   *
   * @return string
   */
  public function get_Nessus_ID() {
    return $this->nessus_id;
  }

  /**
   * Setter function for Nessus ID
   *
   * @param string $str_Nessus_ID
   */
  public function set_Nessus_ID($str_Nessus_ID) {
    $this->nessus_id = $str_Nessus_ID;
  }

  /**
   * Getter function for plugin name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for plugin name
   *
   * @param string $str_Name_In
   */
  public function set_Name($str_Name_In) {
    $this->name = $str_Name_In;
  }

  /**
   * Getter function for plugin summary
   *
   * @return string|null
   */
  public function get_Summary() {
    if (isset($this->refs['summary'])) {
      return $this->refs['summary'];
    }
    return null;
  }

  /**
   * Getter function for plugin description
   *
   * @return string|null
   */
  public function get_Description() {
    if (isset($this->refs['description'])) {
      return $this->refs['description'];
    }
    return null;
  }

  /**
   * Getter function for plugin solution
   *
   * @return string
   */
  public function get_Solution() {
    if (isset($this->refs['solution'])) {
      return $this->refs['solution'];
    }
    return null;
  }

  /**
   * Getter function for plugin family
   *
   * @return string
   */
  public function get_Family() {
    if (isset($this->refs['family'])) {
      return $this->refs['family'];
    }
    return null;
  }

  /**
   * Getter function for plugin category
   *
   * @return string
   */
  public function get_Category() {
    if (isset($this->refs['category'])) {
      return $this->refs['category'];
    }
    return null;
  }

  /**
   * Getter function for plugin copyright
   *
   * @return string
   */
  public function get_Copyright() {
    return $this->copyright;
  }

  /**
   * Setter function for plugin copyright
   *
   * @param string $str_Copyright_In
   */
  public function set_Copyright($str_Copyright_In) {
    $this->copyright = $str_Copyright_In;
  }

  /**
   * Getter function for plugin protocol
   *
   * @return string
   */
  public function get_Protocol() {
    if (isset($this->refs['protocol'])) {
      return $this->refs['protocol'];
    }
    return null;
  }

  /**
   * Getter function for plugin version
   *
   * @return string
   */
  public function get_Version() {
    return $this->version;
  }

  /**
   * Setter function for plugin version
   *
   * @param string $str_Version_In
   */
  public function set_Version($str_Version_In) {
    $this->version = $str_Version_In;
  }

  /**
   * Getter function for plugin file name
   *
   * @return string
   */
  public function get_FileName() {
    return $this->file_name;
  }

  /**
   * Setter function for plugin file name
   *
   * @param string $str_FileName_In
   */
  public function set_FileName($str_FileName_In) {
    $this->file_name = $str_FileName_In;
  }

  /**
   * Getter function for plugin file date
   *
   * @return string
   */
  public function get_FileDate() {
    return $this->file_date;
  }

  /**
   * Getter function for plugin file date
   *
   * @return DateTime
   */
  public function get_FileDate_Date() {
    return DateTime::createFromFormat("U", $this->file_date);
  }

  /**
   * Setter function for plugin file date
   *
   * @param string $str_FileDate_In
   */
  public function set_FileDate($str_FileDate_In) {
    $this->file_date = $str_FileDate_In;
  }

  /**
   * Function to return multidimensional array of all references
   *
   * @return multitype:string
   */
  public function get_Reference() {
    return $this->refs;
  }

  /**
   * Function to return an array of references
   *
   * @param string $type
   *    The type you want to isolate
   *
   * @return multitype:string
   *    Returns an array of references that are linked to a type
   */
  public function get_Reference_By_Type($type) {
    if ($type == 'iavm') {
      $tmp = array();
      if (isset($this->refs['iava'])) {
        $tmp = array_merge($tmp, $this->refs['iava']);
      }
      if (isset($this->refs['iavb'])) {
        $tmp = array_merge($tmp, $this->refs['iavb']);
      }
      if (isset($this->refs['iavt'])) {
        $tmp = array_merge($tmp, $this->refs['iavt']);
      }

      return $tmp;
    }
    if (isset($this->refs[strtolower($type)])) {
      return $this->refs[strtolower($type)];
    }

    return array();
  }

  /**
   * Function to see if a reference is already in the array
   *
   * @param string $type
   *    The reference type you are searching for
   * @param string $val
   *    The value you are searching for
   *
   * @return boolean
   *    Returns TRUE if found, otherwise false
   */
  public function ref_Found($type, $val) {
    if (isset($this->refs[strtolower($type)])) {
      foreach ($this->refs[strtolower($type)] as $ref) {
        if ($ref == $val) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Function to add a reference to the array
   *
   * @param string $type
   *    An enumerated type of reference ('cve','bid','osvdb','edb','iavm','msft','cert','cwe')
   * @param string $val
   *    The type value
   */
  public function add_Reference($type, $val) {
    $this->refs[strtolower($type)][] = $val;
  }

  /**
   * Function to remove a reference
   *
   * @param string $type
   *    An enumerated type of reference ('cve','bid','osvdb','edb','iavm','msft','cert','cwe')
   *    More can be added if necessary
   * @param string $val
   *    The value of the type
   *
   * @return boolean
   *    Returns TRUE if successful, otherwise false
   */
  public function remove_Reference($type, $val) {
    foreach ($this->ref[strtolower($type)] as $key => $ref) {
      if ($ref == $val) {
        unset($this->ref[$key]);
        return true;
      }
    }

    return false;
  }

  /**
   * To compare the meta data in two different nessus objects
   *
   * @param nessus $refs
   *
   * @return array
   */
  public function compare_References($refs) {
    $ret = array();
    foreach ($this->refs as $type => $ref) {
      foreach ($ref as $val) {
        if (!$refs->ref_Found($type, $val)) {
          $ret[$type][] = $val;
        }
      }
    }

    return $ret;
  }

}
