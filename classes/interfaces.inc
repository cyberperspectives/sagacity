<?php

/**
 * File: interfaces.inc
 * Author: Ryan Prather
 * Purpose: Represents an interface that is assigned to a target
 * Created: Sep 16, 2013
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
 *  - Sep 16, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright and converted to use generic port class
 *  - Oct 24, 2016 - Fixed bug with direct call to tcp_port and udp_port private variables (#6)
 *  - Jul 31, 2017 - Fixed bug #280 with updating tcp and udp port notes and banner.
 *  - Aug 14, 2017 - Fixed bug for absent tcp and udp ports when updating. (#284)
 *  - Oct 23, 2017 - Added MAC
 */

/**
 * Class to represent a hardware interface
 *
 * @author Ryan Prather
 */
class interfaces {

  /**
   * Integer used in the database for interfaces ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Integer used in database for Target ID
   *
   * @var integer
   */
  protected $tgt_id = 0;

  /**
   * String to store the name of the interface
   *
   * @var string
   */
  protected $name = '';

  /**
   * String to store the interface Media Access Control (MAC) address
   * @var string
   */
  protected $mac = '';

  /**
   * String to store the ipv4 of the interface
   *
   * @var string
   */
  protected $ipv4 = '';

  /**
   * String to store the ipv6 of the interface
   *
   * @var string
   */
  protected $ipv6 = '';

  /**
   * String to store the hostname of the interface
   *
   * @var string
   */
  protected $hostname = '';

  /**
   * Array of TCP ports open on this interface
   *
   * @var array:tcp_ports
   */
  protected $tcp_ports = array();

  /**
   * Array of UDP ports open on this interface
   *
   * @var array:udp_ports
   */
  protected $udp_ports = array();

  /**
   * String to store the fully qualified domain name (fqdn) of the interface
   *
   * @var string
   */
  protected $fqdn = '';

  /**
   * String to store the description of the interface
   *
   * @var string
   */
  protected $description = '';

  /**
   * Interface notes
   *
   * @var string
   */
  protected $notes = '';

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param integer $int_TGT_ID
   * @param string $str_Name
   * @param string $str_Ipv4
   * @param string $str_Ipv6
   * @param string $str_Hostname
   * @param string $str_FQDN
   * @param string $str_Description
   */
  public function __construct($int_ID, $int_TGT_ID, $str_Name, $str_Ipv4, $str_Ipv6, $str_Hostname, $str_FQDN, $str_Description) {
    $this->id = $int_ID;
    $this->tgt_id = $int_TGT_ID;
    $this->name = $str_Name;
    $this->ipv4 = $str_Ipv4;
    $this->ipv6 = $str_Ipv6;
    $this->hostname = $str_Hostname;
    $this->fqdn = $str_FQDN;
    $this->description = $str_Description;
  }

  /**
   * Getter function for interface ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Setter function for interface ID
   *
   * @param interface $int_id_in
   */
  public function set_ID($int_id_in) {
    $this->id = $int_id_in;
  }

  /**
   * Getter function for target ID
   *
   * @return integer
   */
  public function get_TGT_ID() {
    return $this->tgt_id;
  }

  /**
   * Setter function for the target id
   *
   * @param integer $int_tgt_id_in
   */
  public function set_TGT_ID($int_tgt_id_in) {
    $this->tgt_id = $int_tgt_id_in;
  }

  /**
   * Getter function for interface name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for interface name
   *
   * @param string $str_Name
   */
  public function set_Name($str_Name) {
    $this->name = $str_Name;
  }

  /**
   * Getter function for the interface MAC
   *
   * @return string
   */
  public function get_MAC() {
    return $this->mac;
  }

  /**
   * Setter function for the interface MAC
   *
   * @param string $mac
   */
  public function set_MAC($mac) {
    $this->mac = $mac;
  }

  /**
   * Getter function for interface IPv4 address
   *
   * @return string
   */
  public function get_IPv4() {
    return $this->ipv4;
  }

  /**
   * Setter function for interface IPv4 address
   *
   * @param string $str_Ipv4
   */
  public function set_IPv4($str_Ipv4) {
    $this->ipv4 = $str_Ipv4;
  }

  /**
   * Getter function for interface IPv6 address
   *
   * @return string
   */
  public function get_IPv6() {
    return $this->ipv6;
  }

  /**
   * Setter function for interface IPv6 address
   *
   * @param string $str_Ipv6
   */
  public function set_IPv6($str_Ipv6) {
    $this->ipv6 = $str_Ipv6;
  }

  /**
   * Getter function for hostname
   *
   * @return string
   */
  public function get_Hostname() {
    return $this->hostname;
  }

  /**
   * Setter function for hostname
   *
   * @param string $str_Hostname
   */
  public function set_Hostname($str_Hostname) {
    $this->hostname = $str_Hostname;
  }

  /**
   * Getter function for TCP ports
   *
   * @return array:tcp_ports
   */
  public function get_TCP_Ports() {
    return $this->tcp_ports;
  }

  /**
   * Return a TCP Port object of a specific port
   *
   * @param integer $port_number
   *
   * @return NULL|tcp_ports
   */
  public function get_TCP_Port_By_Port_Number($port_number) {
    return isset($this->tcp_ports[$port_number]) ? $this->tcp_ports[$port_number] : null;
  }

  /**
   * Function to check and see if a TCP port is open
   *
   * @param int $port_number
   *
   * @return boolean
   */
  public function is_TCP_Port_Open($port_number) {
    return isset($this->tcp_ports[$port_number]);
  }

  /**
   * Update a specific tcp port
   *
   * @param tcp_ports $tcp_port
   */
  public function update_TCP_Port($tcp_port) {
    if (isset($this->tcp_ports[$tcp_port->get_Port()])) {
      // Get pointer to current port by reference so updates persist upon return
      $cur_port = &$this->tcp_ports[$tcp_port->get_Port()];
      // Get current and new port banner and notes to determine if we need to update.
      $cur_banner = $cur_port->get_Banner();
      $cur_notes = $cur_port->get_Notes();

      $new_banner = $tcp_port->get_Banner();
      $new_notes = $tcp_port->get_Notes();

      // Only update banner if new banner is not already in current banner
      if (!empty($new_banner) && strpos($cur_banner, $new_banner) === false) {
        $cur_port->set_Banner($tcp_port->get_Banner());
      }
      // Only update notes if new notes is not already in current notes
      if (!empty($new_notes) && strpos($cur_notes, $new_notes) === false) {
        $cur_port->append_Notes($tcp_port->get_Notes());
      }
    }
    else {
      $this->tcp_ports[$tcp_port->get_Port()] = $tcp_port;
    }
  }

  /**
   * Setter function for TCP ports
   *
   * @param tcp_ports $tcp_Ports
   */
  public function add_TCP_Ports($tcp_Ports) {
    if (!isset($this->tcp_ports[$tcp_Ports->get_Port()])) {
      $this->tcp_ports[$tcp_Ports->get_Port()] = $tcp_Ports;
    }
    else {
      if (empty($this->tcp_ports[$tcp_Ports->get_Port()]->get_Banner())) {
        $this->tcp_ports[$tcp_Ports->get_Port()]->set_Banner($tcp_Ports->get_Banner());
      }
      else {
        $this->tcp_ports[$tcp_Ports->get_Port()]->set_Banner($this->tcp_ports[$tcp_Ports->get_Port()]->get_Banner() . PHP_EOL . $tcp_Ports->get_Banner());
      }
    }
  }

  /**
   * Setter function for TCP ports based on array
   *
   * @param integer $port_number
   */
  public function remove_TCP_Ports_Array($port_number) {
    unset($this->tcp_ports[$port_number]);
  }

  /**
   * Getter function for UDP ports
   *
   * @return array:udp_ports
   */
  public function get_UDP_Ports() {
    return $this->udp_ports;
  }

  /**
   * Return a UDP Port object of a specific port
   *
   * @param integer $port_number
   *
   * @return NULL|udp_ports
   */
  public function get_UDP_Port_By_Port_Number($port_number) {
    return isset($this->udp_port[$port_number]) ? $this->udp_ports[$port_number] : null;
  }

  /**
   * Function to check and see if a UDP port is open
   *
   * @param int $port_number
   *
   * @return boolean
   */
  public function is_UDP_Port_Open($port_number) {
    return isset($this->udp_ports[$port_number]);
  }

  /**
   * Update a specific udp port
   *
   * @param udp_ports $udp_port
   */
  public function update_UDP_Port($udp_port) {
    if (isset($this->udp_ports[$udp_port->get_Port()])) {
      // Get pointer to current port by reference so updates persist upon return
      $cur_port = &$this->udp_ports[$udp_port->get_Port()];
      // Get current and new port banner and notes to determine if we need to update.
      $cur_banner = $cur_port->get_Banner();
      $cur_notes = $cur_port->get_Notes();

      $new_banner = $udp_port->get_Banner();
      $new_notes = $udp_port->get_Notes();

      // Only update banner if new banner is not already in current banner
      if (!empty($new_banner) && strpos($cur_banner, $new_banner) === false) {
        $cur_port->set_Banner($udp_port->get_Banner());
      }
      // Only update notes if new notes is not already in current notes
      if (!empty($new_notes) && strpos($cur_notes, $new_notes) === false) {
        $cur_port->append_Notes($udp_port->get_Notes());
      }
    }
    else {
      $this->udp_ports[$udp_port->get_Port()] = $udp_port;
    }
  }

  /**
   * Setter function for UDP ports
   *
   * @param udp_ports $udp_Ports
   */
  public function add_UDP_Ports($udp_Ports) {
    if (!isset($this->udp_ports[$udp_Ports->get_Port()])) {
      $this->udp_ports[$udp_Ports->get_Port()] = $udp_Ports;
    }
    else {
      if (!$this->udp_ports[$udp_Ports->get_Port()]->get_Banner()) {
        $this->udp_ports[$udp_Ports->get_Port()]->set_Banner($udp_Ports->get_Banner());
      }
      else {
        $this->udp_ports[$udp_Ports->get_Port()]->set_Banner($this->udp_ports[$udp_Ports->get_Port()]->get_Banner() . PHP_EOL . $udp_Ports->get_Banner());
      }
    }
  }

  /**
   * Function to remove port from array
   *
   * @param integer $port_number
   */
  public function remove_UDP_Ports_Array($port_number) {
    unset($this->udp_ports[$port_number]);
  }

  /**
   * Getter function for FQDN
   *
   * @return string
   */
  public function get_FQDN() {
    return $this->fqdn;
  }

  /**
   * Setter function for FQDN
   *
   * @param string $str_FQDN
   */
  public function set_FQDN($str_FQDN) {
    $this->fqdn = $str_FQDN;
  }

  /**
   * Getter function for Description
   *
   * @return string
   */
  public function get_Description() {
    return $this->description;
  }

  /**
   * Setter function for Description
   *
   * @param string $str_Description
   */
  public function set_Description($str_Description) {
    $this->description = $str_Description;
  }

  /**
   * Getter function for interface notes
   *
   * @return string
   */
  public function get_Notes() {
    return $this->notes;
  }

  /**
   * Setter function for interface notes
   *
   * @param string $notes_in
   */
  public function set_Notes($notes_in) {
    $this->notes = $notes_in;
  }

  /**
   * Getter function for preformated table row
   *
   * @return string
   */
  public function get_Table_Data($Odd_Row) {
    $ret = "<tr";

    if ($Odd_Row) {
      $ret .= " class='DynamicContent odd_row'";
    }
    else {
      $ret .= " class='DynamicContent even_row'";
    }

    $ret .= "><td><input type='text' style='width:100px;' name='ip[$this->id]' value='$this->ipv4' title='Type DELETE to remove the interface' /></td>";
    $ret .= "<td><input type='text' style='width:215px;' name='hostname[$this->id]' value='$this->hostname'/></td>";
    $ret .= "<td><input type='text' style='width:215px;' name='name[$this->id]' value='$this->name'/></td>";
    $ret .= "<td><input type='text' style='width:215px;' name='fqdn[$this->id]' value='$this->fqdn'/></td>";
    $ret .= "<td><textarea style='width:390px;vertical-align:bottom;' rows='2' name='description[$this->id]'>$this->description</textarea></td></tr>";

    return $ret;
  }

}
