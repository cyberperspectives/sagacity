<?php

/**
 * File: sites.inc
 * Author: Ryan Prather
 * Purpose: This file will instantiate a site object
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
 *  - Sep 1, 2016 - Updated Copyright and added comments
 */

/**
 * Represents a physical site location where the ST&E is taking place
 *
 * @author Ryan Prather
 *
 */
class site {

  /**
   * Site ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Site Name
   *
   * @var string
   */
  protected $name = '';

  /**
   * Site address
   *
   * @var string
   */
  protected $add = '';

  /**
   * Site city
   *
   * @var string
   */
  protected $city = '';

  /**
   * Site state
   *
   * @var string
   */
  protected $state = '';

  /**
   * Site zip
   *
   * @var string
   */
  protected $zip = '';

  /**
   * Site country
   *
   * @var string
   */
  protected $country = '';

  /**
   * Site POC Name
   *
   * @var string
   */
  protected $poc_name = '';

  /**
   * Site POC E-mail
   *
   * @var string
   */
  protected $poc_email = '';

  /**
   * Site POC Phone
   *
   * @var string
   */
  protected $poc_phone = '';

  /**
   * Constructor
   *
   * @param int $intId
   * @param string $strName
   * @param string $strAdd
   * @param string $strCity
   * @param string $strState
   * @param string $strZip
   * @param string $strCountry
   * @param string $strPOC_Name
   * @param string $strPOC_Email
   * @param string $strPOC_Phone
   */
  public function __construct($intId, $strName, $strAdd, $strCity, $strState, $strZip, $strCountry, $strPOC_Name, $strPOC_Email, $strPOC_Phone) {
    $this->id = $intId;
    $this->name = $strName;
    $this->add = $strAdd;
    $this->city = $strCity;
    $this->state = $strState;
    $this->zip = $strZip;
    $this->country = $strCountry;
    $this->poc_email = $strPOC_Email;
    $this->poc_name = $strPOC_Name;
    $this->poc_phone = $strPOC_Phone;
  }

  /**
   * Getter function for the site id
   *
   * @return integer
   */
  public function get_Id() {
    return $this->id;
  }

  /**
   * Setter function for site ID
   *
   * @param integer $id_in
   */
  public function set_ID($id_in) {
    $this->id = $id_in;
  }

  /**
   * Getter function for the site name
   *
   * @return string
   */
  public function get_Name() {
    return $this->name;
  }

  /**
   * Setter function for the site name
   *
   * @param string $str_Name
   */
  public function set_Name($str_Name) {
    $this->name = $str_Name;
  }

  /**
   * Getter function for the site address
   *
   * @return string
   */
  public function get_Address() {
    return $this->add;
  }

  /**
   * Setter function for the site address
   *
   * @param string $str_Address
   */
  public function set_Address($str_Address) {
    $this->add = $str_Address;
  }

  /**
   * Getter function for the site city
   *
   * @return string
   */
  public function get_City() {
    return $this->city;
  }

  /**
   * Setter function for the site city
   *
   * @param string $str_City
   */
  public function set_City($str_City) {
    $this->city = $str_City;
  }

  /**
   * Getter function for the site state
   *
   * @return string
   */
  public function get_State() {
    return $this->state;
  }

  /**
   * Setter function for the site state
   *
   * @param string $str_State
   */
  public function set_State($str_State) {
    $this->state = $str_State;
  }

  /**
   * Getter function for the site zip
   *
   * @return string
   */
  public function get_Zip() {
    return $this->zip;
  }

  /**
   * Setter function for the site zip
   *
   * @param string $str_Zip
   */
  public function set_Zip($str_Zip) {
    $this->zip = $str_Zip;
  }

  /**
   * Getter function for the site country
   *
   * @return string
   */
  public function get_Country() {
    return $this->country;
  }

  /**
   * Setter function for the site country
   *
   * @param string $str_Country
   */
  public function set_Country($str_Country) {
    $this->country = $str_Country;
  }

  /**
   * Getter function for the POC E-mail
   *
   * @return string
   */
  public function get_POC_Email() {
    return $this->poc_email;
  }

  /**
   * Setter function for the POC Email
   *
   * @param string $str_POC_Email
   */
  public function set_POC_Email($str_POC_Email) {
    $this->poc_email = $str_POC_Email;
  }

  /**
   * Getter function for the POC Name
   *
   * @return string
   */
  public function get_POC_Name() {
    return $this->poc_name;
  }

  /**
   * Setter for the POC Name
   *
   * @param string $str_POC_Name
   */
  public function set_POC_Name($str_POC_Name) {
    $this->poc_name = $str_POC_Name;
  }

  /**
   * Getter for the POC Phone
   *
   * @return string
   */
  public function get_POC_Phone() {
    return $this->poc_phone;
  }

  /**
   * Setter for the POC Phone
   *
   * @param string $str_POC_Phone
   */
  public function set_POC_Phone($str_POC_Phone) {
    $this->poc_phone = $str_POC_Phone;
  }

  /**
   * Getter function for preformated &lt;option&gt; tag
   *
   * @param boolean $selectedSite
   * @return string
   */
  public function get_Option($selectedSite = null) {
    return "<option value='" . $this->id . "'" . ($selectedSite ? " selected" : "") .
        ">" . $this->name . "</option>";
  }

}
