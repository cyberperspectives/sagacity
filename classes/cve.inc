<?php
/**
 * File: cve.inc
 * Author: Ryan Prather
 * Purpose: Represents a CVE
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
 * Represents a CVE
 *
 * @author Ryan Prather
 *
 */
class cve {

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * CVE ID
   *
   * @var string
   */
  protected $cve = '';

  /**
   * Sequence ID
   *
   * @var string
   */
  protected $seq = '';

  /**
   * Status of the CVE entry (Entry, Candidate)
   *
   * @var string
   */
  protected $status = '';

  /**
   * Phase of the CVE entry (modified, proposed, interim, assigned)
   *
   * @var string
   */
  protected $phase = '';

  /**
   * Date the phase was last changed
   *
   * @var string
   */
  protected $phase_date = '';

  /**
   * Description of the CVE
   *
   * @var string
   */
  protected $desc = '';

  /**
   * IAVM Notice ID
   *
   * @var array
   */
  protected $iavm = array();

  /**
   * Array of references
   *
   * @var multiple:cve_reference
   */
  protected $ref = array();

  /**
   * XML content from the original CVE
   *
   * @var string
   */
  protected $xml = '';

  /**
   * Constructor
   *
   * @param integer $int_PDI_ID
   * @param string $str_CVE
   */
  public function __construct($int_PDI_ID, $str_CVE) {
    $this->pdi_id = $int_PDI_ID;
    $this->cve = $str_CVE;
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
   * Getter function CVE
   *
   * @return string
   */
  public function get_CVE() {
    return $this->cve;
  }

  /**
   * Setter function for CVE
   *
   * @param string $str_CVE
   */
  public function set_CVE($str_CVE) {
    $this->cve = $str_CVE;
  }

  /**
   * Getter method for sequence
   *
   * @return string
   */
  public function get_Sequence() {
    return $this->seq;
  }

  /**
   * Setter function for Sequence
   *
   * @param string $str_Seq_In
   */
  public function set_Sequence($str_Seq_In) {
    $this->seq = $str_Seq_In;
  }

  /**
   * Getter method for status
   *
   * @return string
   */
  public function get_Status() {
    return $this->status;
  }

  /**
   * Setter method for status
   *
   * @param string $str_Status_In
   */
  public function set_Status($str_Status_In) {
    $this->status = $str_Status_In;
  }

  /**
   * Getter function for phase
   *
   * @return string
   */
  public function get_Phase() {
    return $this->phase;
  }

  /**
   * Setter function for phase
   *
   * @param string $str_Phase_In
   */
  public function set_Phase($str_Phase_In) {
    $this->phase = $str_Phase_In;
  }

  /**
   * Getter function for phase date
   *
   * @return string
   */
  public function get_Phase_Date() {
    return $this->phase_date;
  }

  /**
   * Getter function for phase date as DateTime
   *
   * @return DateTime
   */
  public function get_Phase_Date_Date() {
    return new DateTime($this->phase_date);
  }

  /**
   * Setter function for phase date
   *
   * @param string $str_Phase_Date_In
   */
  public function set_Phase_Date($str_Phase_Date_In) {
    if(is_string($str_Phase_Date_In)) {
      $this->phase_date = $str_Phase_Date_In;
    }
    elseif(is_a($str_Phase_Date_In, "DateTime")) {
      $this->phase_date = $str_Phase_Date_In->format(DATE_W3C);
    }
  }

  /**
   * Getter function for CVE description
   *
   * @return string
   */
  public function get_Description() {
    return $this->desc;
  }

  /**
   * Setter function for the CVE description
   *
   * @param string $str_Description_In
   */
  public function set_Description($str_Description_In) {
    $this->desc = $str_Description_In;
  }

  /**
   * Getter functio for the IAVM Notice ID
   *
   * @return array
   */
  public function get_IAVM() {
    return $this->iavm;
  }

  /**
   * Setter function for the IAVM Notice ID
   *
   * @param string $iavm_in
   */
  public function add_IAVM($iavm_in) {
    if(!in_array($iavm_in, $this->iavm)) {
      $this->iavm[] = $iavm_in;
    }
  }

  /**
   * Getter function for cve reference array
   *
   * @return array:cve_reference
   */
  public function get_References() {
    return $this->ref;
  }

  /**
   * Function to add cve reference to array
   *
   * @param cve_reference $ref_in
   */
  public function add_Reference($ref_in) {
    $this->ref[] = $ref_in;
  }

  /**
   * Function to see if a reference exists in this CVE
   *
   * @param string $ref_in
   */
  public function ref_Exists($ref_in) {
    foreach($this->ref as $key => $ref) {
      if($ref->get_Value() == $ref_in) {
        return $ref;
      }
    }

    return false;
  }

  /**
   * Function to remove reference from array
   *
   * Return true if found and removed, otherwise false
   *
   * @param cve_reference $ref_in
   * @return boolean
   */
  public function remove_Reference($ref_in) {
    foreach($this->ref as $key => $ref) {
      if($ref->get_ID() == $ref_in->get_ID()) {
        unset($this->ref[$key]);
        return true;
      }
    }

    return false;
  }

  /**
   * Getter function for CVE XML
   *
   * @return string
   */
  public function get_XML() {
    return $this->xml;
  }

  /**
   * Setter function for CVE XML
   *
   * @param string $xml_in
   */
  public function set_XML($xml_in) {
    $this->xml = $xml_in;
  }
}

/**
 * Represent a CVE Reference
 *
 * @author Ryan Prather
 */
class cve_reference {
  /**
   * Reference ID from DB
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Reference source
   *
   * @var string
   */
  protected $source = '';

  /**
   * CVE URL
   *
   * @var string
   */
  protected $url = '';

  /**
   * CVE Reference value
   *
   * @var string
   */
  protected $val = '';

  /**
   * Constructor
   *
   * @param integer $int_ID_In
   * @param string $str_Source_In
   * @param string $str_URL_In
   * @param string $str_Val_In
   */
  public function __construct($int_ID_In, $str_Source_In, $str_URL_In, $str_Val_In) {
    $this->id = $int_ID_In;
    $this->source = $str_Source_In;
    $this->url = $str_URL_In;
    $this->val = $str_Val_In;
  }

  /**
   * Getter function for reference id
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter function for reference source
   *
   * @return string
   */
  public function get_Source() {
    return $this->source;
  }

  /**
   * Getter function for reference URL
   *
   * @return string
   */
  public function get_URL() {
    return $this->url;
  }

  /**
   * Getter function for reference value
   *
   * @return string
   */
  public function get_Value() {
    return $this->val;
  }
}