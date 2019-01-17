<?php

/**
 * File: software.inc
 * Author: Ryan Prather
 * Purpose: Represents a software package that can be installed on target
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
 *  - Sep 1, 2016 - Updated Copyright, added a few comments, and refined the reduce_CPE functionality
 *  - Oct 24, 2016 - Update identify_Software function replaced $chk_id with $sw_in
 *  - Nov 7, 2016 - Removed a couple print statements
 *  - Nov 9, 2016 - Formatting, added get_Reduce_Count function,
 *                  Added check in identify_Software to see if $sw_in is a CPE already
 *  - Dec 12, 2016 - Added software reduction if version contains '-'
 *  - Mar 3, 2017 - Bug fixes to reduce_CPE method
 */

/**
 * Represents a software package that can be installed on a target
 *
 * @author Ryan Prather
 *
 */
class software {

  /**
   * Software ID
   *
   * @var integer
   */
  public $id = 0;

  /**
   * Software manufacturer
   *
   * @var string
   */
  public $man = '';

  /**
   * Software name
   *
   * @var string
   */
  public $name = '';

  /**
   * Software version
   *
   * @var string
   */
  public $ver = '';

  /**
   * Software build string
   *
   * @var string
   */
  public $build = '';

  /**
   * Software build date
   *
   * @var DateTime
   */
  public $date;

  /**
   * Software architecture
   *
   * @var string
   *    x86, x64, ia64
   */
  private $arch = '';

  /**
   * Manual
   *
   * @var boolean
   */
  public $manual = false;

  /**
   * Is this software an operating system
   *
   * @var boolean
   */
  public $os = false;

  /**
   * Software service pack
   *
   * @var string
   */
  public $sp = '';

  /**
   * CPE string
   *
   * @var string
   */
  private $cpe = '';

  /**
   * CPE v2.3 string
   *
   * @var string
   */
  private $cpe23 = '';

  /**
   * The software string
   *
   * @var string
   */
  private $sw_string = '';

  /**
   * Shortened software string
   *
   * @var string
   */
  private $short_sw_string = '';

  /**
   * Variable to know how many times this software has been reduced
   *
   * @var int
   */
  private $reduce_count = 0;

  /**
   * Constructor
   *
   * @param string $cpe
   * @param string $cpe23
   */
  public function __construct($cpe, $cpe23) {
    $this->cpe = $cpe;
    $this->cpe23 = $cpe23;

    if (!empty($this->cpe23)) {
      $arr = explode(":", $this->cpe23);

      $this->os = ($arr[2] == 'o' ? true : false);
      $this->man = (isset($arr[3]) ? ucwords(str_replace("_", " ", $arr[3])) : "*");
      $this->name = (isset($arr[4]) ? ucwords(str_replace("_", " ", $arr[4])) : "*");
      $this->ver = (isset($arr[5]) ? ucwords(str_replace("_", " ", $arr[5])) : "-");
      $this->sp = (isset($arr[6]) ? ucwords(str_replace("_", " ", $arr[6])) : "");
    }

    if (!empty($this->cpe)) {
      $arr = explode(":", $this->cpe);

      if (empty($cpe23)) {
        $this->os = ($arr[1] == '/o' ? true : false);
        $this->man = (isset($arr[2]) ? ucwords(str_replace("_", " ", $arr[2])) : "*");
        $this->name = (isset($arr[3]) ? ucwords(str_replace("_", " ", $arr[3])) : "*");
        $this->ver = (isset($arr[4]) ? ucwords(str_replace("_", " ", $arr[4])) : "-");
        $this->sp = (isset($arr[5]) ? ucwords(str_replace("_", " ", $arr[5])) : "");

        $this->cpe23 = "cpe:2.3:" .
            ($arr[1] == '/o' ? 'o' : 'a') . ":" .
            $this->man . ":" .
            $this->name . ":" .
            $this->ver . ":" .
            (!empty($this->sp) ? $this->sp : "*") . ":*:*:*:*:*:*";

        $this->cpe23 = strtolower(str_replace(" ", "_", $this->cpe23));
      }
    }

    $this->reduce_count = 0;
  }

  /**
   * Getter function for Software ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Setter function for Software ID
   *
   * @param integer $sw_id_in
   *    Value to set the ID to
   */
  public function set_ID($sw_id_in) {
    $this->id = $sw_id_in;
  }

  /**
   * Getter function for manufacturer
   *
   * @return string
   */
  public function get_Man() {
    return $this->man;
  }

  /**
   * Setter function for manufacturer
   *
   * @param string $str_Man
   */
  public function set_Man($str_Man) {
    $this->man = $str_Man;
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
   * Setter function for name
   *
   * @param string $str_Name
   */
  public function set_Name($str_Name) {
    $this->name = $str_Name;
  }

  /**
   * Getter function for version
   *
   * @return string
   */
  public function get_Version() {
    return $this->ver;
  }

  /**
   * Setter function for version
   *
   * @param string $str_Version
   */
  public function set_Version($str_Version) {
    $this->ver = $str_Version;
  }

  /**
   * Getter function for build string
   *
   * @return string
   */
  public function get_Build() {
    return $this->build;
  }

  /**
   * Setter function for build string
   *
   * @param string $str_Build
   */
  public function set_Build($str_Build) {
    $this->build = $str_Build;
  }

  /**
   * Getter funciton for build date
   *
   * @return DateTime
   */
  public function get_Build_Date() {
    return $this->date;
  }

  /**
   * Setter function for build date
   *
   * @param string $dt_Build_Date
   */
  public function set_Build_Date($dt_Build_Date) {
    $this->date = new DateTime($dt_Build_Date);
  }

  /**
   * Getter function for manual
   *
   * @return boolean
   */
  public function is_Manual() {
    return $this->manual;
  }

  /**
   * Setter function for manual
   *
   * @param boolean $bln_Manual
   */
  public function set_Manual($bln_Manual) {
    $this->manual = $bln_Manual;
  }

  /**
   * Getter function for operation system
   *
   * @return boolean
   */
  public function is_OS() {
    return $this->os;
  }

  /**
   * Setter function for operating system
   *
   * @param boolean $bln_OS
   */
  public function set_OS($bln_OS) {
    $this->os = $bln_OS;
  }

  /**
   * Getter function for service pack
   *
   * @return string
   */
  public function get_SP() {
    return $this->sp;
  }

  /**
   * Setter fucntion for service pack
   *
   * @param string $str_SP
   */
  public function set_SP($str_SP) {
    $this->sp = $str_SP;
  }

  /**
   * Getter function for software string
   *
   * @return string
   */
  public function get_SW_String() {
    return $this->sw_string;
  }

  /**
   * Setter function for software string
   *
   * @param string $sw_string_in
   */
  public function set_SW_String($sw_string_in) {
    $this->sw_string = $sw_string_in;
  }

  /**
   * To get the shortened software string
   *
   * @return string
   */
  public function get_Shortened_SW_String() {
    return $this->short_sw_string;
  }

  /**
   * To set the shortened software string
   *
   * @param string $sw_string_in
   */
  public function set_Shortened_SW_String($sw_string_in) {
    $this->short_sw_string = $sw_string_in;
  }

  /**
   * Getter function for the CPE string
   *
   * @return string
   */
  public function get_CPE($refresh = false) {
    if ($refresh) {
      $cpe = "cpe:" .
          ($this->os ? "/o" : "/a") . ":" .
          (isset($this->man) ? $this->man : "*") . ":" .
          (isset($this->name) ? $this->name : "*") . ":" .
          (isset($this->ver) ? $this->ver : "") .
          (!empty($this->sp) ? ":" . $this->sp : "");

      $this->cpe = strtolower(str_replace(" ", "_", $cpe));

      $cpe23 = "cpe:2.3:" .
          ($this->os ? "o" : "a") . ":" .
          (isset($this->man) ? $this->man : "*") . ":" .
          (isset($this->name) ? $this->name : "*") . ":" .
          (isset($this->ver) ? $this->ver : "-") .
          (!empty($this->sp) ? ":" . $this->sp : "") . ":*:*:*:*:*:*";

      $this->cpe23 = strtolower(str_replace(" ", "_", $cpe23));
    }

    return $this->cpe;
  }

  /**
   * Setter function for the CPE string
   *
   * @param string $cpe_in
   */
  public function set_CPE($cpe_in) {
    $this->cpe = $cpe_in;
  }

  /**
   * Getter function for the CPE v2.3 string
   *
   * @return string
   */
  public function get_CPE23() {
    return $this->cpe23;
  }

  /**
   * Setter function for the CPE v2.3 string
   *
   * @param string $cpe23_in
   */
  public function set_CPE23($cpe23_in) {
    $this->cpe23 = $cpe23_in;
  }

  /**
   * Getter function for the software architecture
   *
   * @return string
   */
  public function get_Arch() {
    return $this->arch;
  }

  /**
   * Setter function for the software architecture
   *
   * @param string $arch_in
   */
  public function set_Arch($arch_in) {
    $this->arch = $arch_in;
  }

  /**
   * Getter function for the reducing count
   */
  public function get_Reduce_Count() {
    return $this->reduce_count;
  }

  /**
   * Getter function for preformated option tag
   *
   * @return string
   */
  public function print_Option() {
    return "<option value='" . $this->id . "' " .
        "title='$this->sw_string' " .
        ">$this->sw_string</option>";
  }

  /**
   * Function to take the CPE from specific to generic
   *
   * @return boolean
   */
  public function reduce_CPE() {
    switch ($this->reduce_count) {
      case 0:
        // this is to reduce the CPE for Cisco
        if (($pos = strpos($this->ver, "%")) !== false) {
          $this->ver = substr($this->ver, 0, $pos);
        }
        break;
      case 1:
        // this simply allows the removal of the SP/update
        if (!is_null($this->sp)) {
          $this->sp = null;
          break;
        }
        if (($pos = strpos($this->ver, '-')) !== false) {
          $this->ver = substr($this->ver, 0, ($pos > 0 ? $pos : $pos + 1));
        }
        break;
      case 2:
        // this reduces the version to remove any . so that 11.2 becomes 11
        if (($pos = strpos($this->ver, ".")) !== false) {
          $this->ver = substr($this->ver, 0, ($pos > 0 ? $pos : $pos + 1));
        }
        break;
      case 3:
        // this removes the version since the SP is already null
        $this->ver = null;
        break;
    }

    $this->cpe = (substr($this->get_CPE(true), -1) == '-' ? substr($this->get_CPE(true), 0, -1) : $this->get_CPE(true));

    $this->reduce_count++;

    return (is_null($this->sp) && is_null($this->ver) ? true : false);
  }

  /**
   * Function to return the software object for this CPE string
   *
   * @param array $sw_in
   *
   * @return array:software
   */
  public static function toSoftwareFromArray($sw_in) {
    $sw = array();
    foreach ($sw_in as $s) {
      $cpe_str = "cpe:" .
          ($s['type'] ? "/o" : "/a") . ":" .
          (isset($s['man']) ? $s['man'] : "*") . ":" .
          (isset($s['name']) ? $s['name'] : "*") . ":" .
          (isset($s['ver']) ? $s['ver'] : "-") .
          (isset($s['sp']) && !empty($s['sp']) ? ":" . $s['sp'] : "");

      $cpe_str = strtolower(
          str_replace(
              array(" ", "(", ")"), array("_", "%28", "%29"), $cpe_str
          )
      );

      $sw[] = new software($cpe_str, null);
    }

    return $sw;
  }

  /**
   * Function to attempt to identify the software
   *
   * @param array $regex_arr
   *    Array of regular expressions to evaluate the software against
   * @param string $sw_in
   *    The string software to evaluate
   * @param boolean $return_obj [optional]
   *    Boolean to decide if we are returning a software object instead of an array
   *
   * @return array
   */
  public static function identify_Software($regex_arr, $sw_in, $return_obj = false) {
    $looking = true;
    $match = array();
    $ret = array();
    $start = $sw = array(
      'man'   => null,
      'name'  => null,
      'ver'   => null,
      'type'  => false,
      'sp'    => null,
      'build' => null
    );

    if (substr($sw_in, 0, 7) == 'cpe:2.3') {
      return new software(null, $sw_in);
    }
    elseif (substr($sw_in, 0, 3) == 'cpe') {
      return new software($sw_in, null);
    }
    else {
      $end = end($regex_arr);
      while ($looking) {
        foreach ($regex_arr as $regex) {
          if (preg_match("/{$regex['rgx']}/i", $sw_in)) {
            $sw['man'] = $regex['man'];
            $start['man'] = $regex['man'];

            foreach ($regex['name'] as $regex2) {
              if ($regex2['name_match'] || $regex2['ver_match'] || $regex2['update_match']) {
                if (preg_match("/{$regex2['rgx']}/i", $sw_in, $match)) {
                  $sw['name'] = $regex2['name'];
                  if (!empty($regex2['man_override'])) {
                    $sw['man'] = $regex2['man_override'];
                  }

                  if ($regex2['name_match']) {
                    foreach (explode(",", $regex2['name_match']) as $idx) {
                      if (isset($match[$idx]) && $match[$idx]) {
                        $sw['name'] .= " " . $match[$idx];
                      }
                    }
                  }

                  if ($regex2['ver_match']) {
                    foreach (explode(",", $regex2['ver_match']) as $idx) {
                      if (isset($match[$idx]) && $match[$idx]) {
                        $sw['ver'] .= $match[$idx] . " ";
                      }
                    }

                    $sw['ver'] = str_replace("_", ".", trim($sw['ver']));

                    if ($sw['man'] == 'Oracle' && $sw['name'] == 'JRE') {
                      $sw['ver'] = "1.{$sw['ver']}.0";
                    }
                    elseif (substr($sw['ver'], -1) == '.') {
                      $sw['ver'] = substr($sw['ver'], 0, -1);
                    }
                  }

                  if (empty($sw['ver'])) {
                    if (!empty($regex2['ver'])) {
                      $sw['ver'] = $regex2['ver'];
                    }
                    else {
                      $sw['ver'] = "-";
                    }
                  }

                  if ($regex2['update_match']) {
                    foreach (explode(",", $regex2['update_match']) as $idx) {
                      if (isset($match[$idx]) && !empty($match[$idx])) {
                        if (preg_match("/service pack [\d]+/i", $match[$idx])) {
                          $sw['sp'] .= preg_replace("/service pack ([\d]+)/i", "sp$1", $match[$idx]) . " ";
                        }
                        elseif ($sw['man'] == 'Oracle' && $sw['name'] == 'JRE') {
                          $sw['sp'] .= "update_" . $match[$idx];
                        }
                        else {
                          $sw['sp'] .= $match[$idx] . " ";
                        }
                      }
                    }

                    $sw['sp'] = trim($sw['sp']);

                    if (substr($sw['sp'], -1) == '.') {
                      $sw['sp'] = substr($sw['sp'], 0, -1);
                    }
                  }
                  else {
                    $sw['sp'] = null;
                  }

                  $sw['type'] = $regex2['is_os'];
                  $ret[] = $sw;

                  if (!$regex2['multiple'])
                    break;

                  $sw = $start;
                }
              }
              else {
                if (preg_match("/{$regex2['rgx']}/i", $sw_in)) {
                  $sw['name'] = $regex2['name'];
                  if (!empty($regex2['man_override'])) {
                    $sw['man'] = $regex2['man_override'];
                  }

                  if (!empty($regex2['ver'])) {
                    $sw['ver'] = $regex2['ver'];
                  }
                  else {
                    $sw['ver'] = "-";
                  }
                  $sw['type'] = $regex2['is_os'];
                  $ret[] = $sw;

                  if (!$regex2['multiple'])
                    break;

                  $sw = $start;
                }
              }
            }

            $looking = false;
            break;
          }

          if ($regex == $end) {
            $looking = false;
            break;
          }
        }
      }
    }

    if ($return_obj) {
      $ret = software::toSoftwareFromArray($ret);
    }

    return $ret;
  }

}
