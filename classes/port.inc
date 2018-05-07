<?php

/**
 * File: ports.inc
 * Author: Ryan Prather
 * Purpose: Represents an open TCP or UDP port on an interface
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
 * Change Log:
 *  - Sep 12, 2013 - File created
 *  - Sep 1, 2016 - Copyright updated
 *  - Oct 24, 2016 - Updated relationship between tcp/udp_port and port classes
 */

/**
 * Represents a generic port
 *
 * @author Ryan Prather
 */
class port {

  /**
   * port ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * port number
   *
   * @var integer
   */
  protected $port = 0;

  /**
   * Name as defined by IANA
   *
   * @var string
   */
  protected $iana_name = '';

  /**
   * Banner
   *
   * @var string
   */
  protected $banner = '';

  /**
   * Port notes
   *
   * @var string
   */
  protected $notes = '';

  /**
   * Getter function for port Id
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter function for port number
   *
   * @return integer
   */
  public function get_Port() {
    return $this->port;
  }

  /**
   * Getter function for port name
   *
   * @return string
   */
  public function get_IANA_Name() {
    return $this->iana_name;
  }

  /**
   * Setter function for port name
   *
   * @return string
   */
  public function set_IANA_Name($str_New_Name) {
    $this->iana_name = $str_New_Name;
  }

  /**
   * Geeter function for port banner
   *
   * @return string
   */
  public function get_Banner() {
    return $this->banner;
  }

  /**
   * Setter function for port notes
   *
   * @param
   *        $str_New_Banner
   */
  public function set_Banner($str_New_Banner) {
    $this->banner = $str_New_Banner;
  }

  /**
   * Getter function for port notes
   *
   * @return string
   */
  public function get_Notes() {
    return $this->notes;
  }

  /**
   * Setter function for port notes
   *
   * @param string $str_New_Notes
   */
  public function set_Notes($str_New_Notes) {
    $this->notes = $str_New_Notes;
  }

  /**
   * Setter function that will append new notes instead of overwriting
   *
   * @param string $str_New_Notes
   */
  public function append_Notes($str_New_Notes) {
    $this->notes .= $str_New_Notes;
  }

}

/**
 * Represents a TCP port/service
 *
 * @author Ryan Prather
 *
 */
class tcp_ports extends port {

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param integer $int_Port
   * @param string $str_IANA_Name
   * @param string $str_Banner
   * @param string $str_Notes
   */
  public function __construct($int_ID, $int_Port, $str_IANA_Name, $str_Banner, $str_Notes) {
    $this->id = $int_ID;
    $this->port = $int_Port;
    $this->iana_name = $str_IANA_Name;
    $this->banner = $str_Banner;
    $this->notes = $str_Notes;
  }

  /**
   * Getter function for preformated table row
   *
   * @return string
   */
  public function get_Table_Data($intface_IP, $intface_ID, $Odd_Row) {
    $ret = "<div class='pps-row " . ($Odd_Row ? "odd" : "even") . "_row'>" .
        "<span class='pps'>" .
        "<input type='hidden' name='tcp_port[$intface_ID][$this->id]' value='$this->port' />$this->port" . "/tcp" .
        "</span>" .
        "<span class='listen'>$intface_IP</span>" .
        "<span class='iana-name'>" .
        "<input type='text' class='auto-update-text' style='width: 150px;' name='iana_name[$intface_ID][$this->id]' value='$this->iana_name'/>" .
        "</span>" .
        "<span class='banner'>" .
        "<textarea class='auto-update-text' style='width: 300px; vertical-align: bottom' rows='2' name='banner[$intface_ID][$this->id]'>$this->banner</textarea>" .
        "</span>" .
        "<span class='pps-notes'>" .
        "<textarea class='auto-update-text' style='width: 450px; vertical-align: bottom' rows='3' name='notes[$intface_ID][$this->id]'>$this->notes</textarea>" .
        "</span>" .
        "</div>";

    return $ret;
  }

}

/**
 * Represents a UDP port/service
 *
 * @author Ryan Prather
 *
 */
class udp_ports extends port {

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param integer $int_Port
   * @param string $str_IANA_Name
   * @param string $str_Banner
   * @param string $str_Notes
   */
  public function __construct($int_ID, $int_Port, $str_IANA_Name, $str_Banner, $str_Notes) {
    $this->id = $int_ID;
    $this->port = $int_Port;
    $this->iana_name = $str_IANA_Name;
    $this->banner = $str_Banner;
    $this->notes = $str_Notes;
  }

  /**
   * Getter function for preformated tabel row
   *
   * @param string $intface_IP
   * @param integer $intface_ID
   * @param boolean $Odd_Row
   * @return string
   */
  public function get_Table_Data($intface_IP, $intface_ID, $Odd_Row) {
    $ret = "<div class='pps-row " . ($Odd_Row ? "odd" : "even") . "_row'>" .
        "<span class='pps'>" .
        "<input type='hidden' name='udp_port[$intface_ID][$this->id]' value='$this->port' />$this->port" . "/udp" .
        "</span>" .
        "<span class='listen'>$intface_IP</span>" .
        "<span class='iana-name'>" .
        "<input type='text' class='auto-update-text' style='width: 150px;' name='iana_name[$intface_ID][$this->id]' value='$this->iana_name'/>" .
        "</span>" .
        "<span class='banner'>" .
        "<textarea class='auto-update-text' style='width: 300px; vertical-align: bottom' rows='2' name='banner[$intface_ID][$this->id]'>$this->banner</textarea>" .
        "</span>" .
        "<span class='pps-notes'>" .
        "<textarea class='auto-update-text' style='width: 450px; vertical-align: bottom' rows='3' name='notes[$intface_ID][$this->id]'>$this->notes</textarea>" .
        "</span>" .
        "</div>";

    return $ret;
  }

}
