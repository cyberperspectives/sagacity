<?php
/**
 * File: iavm.inc
 * Author: Ryan Prather
 * Purpose: Represent an IAVM
 * Created: Jan 22, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 22, 2014 - File created
 */

/**
 * @author Ryan Prather
 */
class iavm {
  /**
   * PDI ID for linked iavm
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * Notice ID
   *
   * @var integer
   */
  protected $notice_id = 0;

  /**
   * XML URL
   *
   * @var string
   */
  protected $xml_url = '';

  /**
   * HTML URL
   *
   * @var string
   */
  protected $html_url = '';

  /**
   * IAVM notice number (YYYY-T-NNNN)
   *
   * @var string
   */
  protected $iavm_notice_num = '';

  /**
   * Title
   *
   * @var string
   */
  protected $title = '';

  /**
   * Type
   *
   * @var string
   */
  protected $type = '';

  /**
   * State
   *
   * @var string
   */
  protected $state = '';

  /**
   * Last updated
   *
   * @var string
   */
  protected $last_updated = '';

  /**
   * Released date
   *
   * @var string
   */
  protected $release_date = '';

  /**
   * Supersedes
   *
   * @var integer
   */
  protected $supersedes = 0;

  /**
   * Executive summary
   *
   * @var string
   */
  protected $exec_summary = '';

  /**
   * Fix action
   *
   * @var string
   */
  protected $fix_action = '';

  /**
   * Notes
   *
   * @var string
   */
  protected $note = '';

  /**
   * Don't know what this means
   *
   * @var string
   */
  protected $vuln_app = '';

  /**
   * STIG severity (cat level)
   *
   * @var integer
   */
  protected $stig_severity = 0;

  /**
   * Known occurances of exploitation
   *
   * @var string
   */
  protected $known_exploits = '';

  /**
   * Linked CVE ID
   *
   * @var array
   */
  protected $cve = array();

  /**
   * IAVM Bugtraq IDs
   *
   * @var multitype:iavm_bid
   */
  protected $iavm_bids = array();

  /**
   * IAVM references
   *
   * @var multitype:iavm_reference
   */
  protected $iavm_refs = array();

  /**
   * IAVM tech overview
   *
   * @var iavm_tech_overview
   */
  protected $iavm_tech_overview = null;

  /**
   * Array of IAVM patches
   *
   * @var multitype:iavm_patch
   */
  protected $iavm_patches = array();

  /**
   * IAVM mitigation
   *
   * @var iavm_mitigation
   */
  protected $iavm_mitigation = null;

  /**
   *
   * @param integer $noticeId_in
   * @param integer $pdi_id_in
   * @param string $xmlUrl_in
   * @param string $htmlUrl_in
   * @param string $noticeNumber_in
   * @param string $title_in
   * @param string $type_in
   * @param string $state_in
   * @param string $lastUpdated_in
   * @param string $releaseDate_in
   * @param integer $supersedes_in
   * @param string $execSum_in
   * @param string $fixAction_in
   * @param string $note_in
   * @param string $vulApps_in
   * @param integer $stigSeverity_in
   * @param string $knownExploits_in
   */
  public function __construct($noticeId_in, $pdi_id_in, $xmlUrl_in, $htmlUrl_in, $noticeNumber_in,
        $title_in, $type_in, $state_in, $lastUpdated_in, $releaseDate_in, $supersedes_in,
        $execSum_in, $fixAction_in, $note_in, $vulApps_in, $stigSeverity_in, $knownExploits_in) {
    $this->notice_id        = $noticeId_in;
    $this->pdi_id           = $pdi_id_in;
    $this->xml_url          = $xmlUrl_in;
    $this->html_url         = $htmlUrl_in;
    $this->iavm_notice_num  = $noticeNumber_in;
    $this->title            = $title_in;
    $this->type             = $type_in;
    $this->state            = $state_in;
    $this->last_updated     = $lastUpdated_in;
    $this->release_date     = $releaseDate_in;
    $this->supersedes       = $supersedes_in;
    $this->exec_summary     = $execSum_in;
    $this->fix_action       = $fixAction_in;
    $this->note             = $note_in;
    $this->vuln_app         = $vulApps_in;
    $this->stig_severity    = $stigSeverity_in;
    $this->known_exploits   = $knownExploits_in;

    $this->iavm_tech_overview = new iavm_tech_overview(null, '');
    $this->iavm_mitigation = new iavm_mitigation(null, '', '');
  }

  /**
   * Getter method for pdi id
   *
   * @return integer
   */
  public function get_PDI_ID() {
    return $this->pdi_id;
  }

  /**
   * Getter method for notice ID
   *
   * @return integer
   */
  public function get_Notice_ID() {
    return $this->notice_id;
  }

  /**
   * Getter method for XML URL
   *
   * @return string
   */
  public function get_XML_URL() {
    return $this->xml_url;
  }

  /**
   * Setter method for XML URL
   *
   * @param string $str_XML_URL_In
   */
  public function set_XML_URL($str_XML_URL_In) {
    $this->xml_url = $str_XML_URL_In;
  }

  /**
   * Getter method for HTML URL
   *
   * @return string
   */
  public function get_HTML_URL() {
    return $this->html_url;
  }

  /**
   * Setter method for HTML URL
   *
   * @param string $str_HTML_URL_In
   */
  public function set_HTML_URL($str_HTML_URL_In) {
    $this->html_url = $str_HTML_URL_In;
  }

  /**
   * Getter method for IAVM Notice Number
   *
   * @return string
   */
  public function get_Notice_Number() {
    return $this->iavm_notice_num;
  }

  /**
   * Setter method for IAVM notice number
   *
   * @param string $str_Notice_Number_In
   */
  public function set_Notice_Number($str_Notice_Number_In) {
    $this->iavm_notice_num = $str_Notice_Number_In;
  }

  /**
   * Getter method for title
   *
   * @return string
   */
  public function get_Title() {
    return $this->title;
  }

  /**
   * Setter method for Title
   *
   * @param string $str_Title_In
   */
  public function set_Title($str_Title_In) {
    $this->title = $str_Title_In;
  }

  /**
   * Getter method for type
   *
   * @return string
   */
  public function get_Type() {
    return $this->type;
  }

  /**
   * Setter method for type
   *
   * @param string $str_Type_In
   */
  public function set_Type($str_Type_In) {
    $this->type = $str_Type_In;
  }

  /**
   * Getter method for state
   *
   * @return string
   */
  public function get_State() {
    return $this->state;
  }

  /**
   * Setter method for state
   *
   * @param string $str_State_In
   */
  public function set_State($str_State_In) {
    $this->state = $str_State_In;
  }

  /**
   * Getter method for last updated
   *
   * @return string
   */
  public function get_Last_Updated() {
    return $this->last_updated;
  }

  /**
   * Getter method for last updated
   *
   * @return DateTime
   */
  public function get_Last_Updated_Date() {
    return new DateTime($this->last_updated);
  }

  /**
   * Setter method for last updated
   *
   * @param string $str_Last_Updated_In
   */
  public function set_Last_Update($str_Last_Updated_In) {
    $this->last_updated = $str_Last_Updated_In;
  }

  /**
   * Getter method for release date
   *
   * @return string
   */
  public function get_Release_Date() {
    return $this->release_date;
  }

  /**
   * Getter method for release date
   *
   * @return DateTime
   */
  public function get_Release_Date_Date() {
    return new DateTime($this->release_date);
  }

  /**
   * Setter method for release date
   *
   * @param string $str_Release_Date_In
   */
  public function set_Release_Date($str_Release_Date_In) {
    $this->release_date = $str_Release_Date_In;
  }

  /**
   * Getter method for supersedes
   *
   * @return integer
   */
  public function get_Supersedes() {
    return $this->supersedes;
  }

  /**
   * Setter method for supersedes
   *
   * @param integer $int_Supersedes_In
   */
  public function set_Supersedes($int_Supersedes_In) {
    $this->supersedes = $int_Supersedes_In;
  }

  /**
   * Getter method for executive summary
   *
   * @return string
   */
  public function get_Executive_Summary() {
    return $this->exec_summary;
  }

  /**
   * Setter method for executive summary
   *
   * @param string $str_Exec_Sum_In
   */
  public function set_Executive_Summary($str_Exec_Sum_In) {
    $this->exec_summary = $str_Exec_Sum_In;
  }

  /**
   * Getter method for fix action
   *
   * @return string
   */
  public function get_Fix_Action() {
    return $this->fix_action;
  }

  /**
   * Setter method for fix action
   *
   * @param string $str_Fix_Action_In
   */
  public function set_Fix_Action($str_Fix_Action_In) {
    $this->fix_action = $str_Fix_Action_In;
  }

  /**
   * Getter method for notes
   *
   * @return string
   */
  public function get_Notes() {
    return $this->note;
  }

  /**
   * Setter method for notes
   *
   * @param string $str_Notes_In
   */
  public function set_Notes($str_Notes_In) {
    $this->note = $str_Notes_In;
  }

  /**
   * Getter method for vulnerable apps
   *
   * @return string
   */
  public function get_Vuln_Apps() {
    return $this->vuln_app;
  }

  /**
   * Setter method for Vulnerable Apps
   *
   * @param string $str_Vuln_Apps_In
   */
  public function set_Vuln_Apps($str_Vuln_Apps_In) {
    $this->vuln_app = $str_Vuln_Apps_In;
  }

  /**
   * Getter method for stig severity
   *
   * @return integer
   */
  public function get_Stig_Severity() {
    return $this->stig_severity;
  }

  /**
   * Setter method for stig severity
   *
   * @param integer $int_Stig_Severity_In
   */
  public function set_Stig_Severity($int_Stig_Severity_In) {
    $this->stig_severity = $int_Stig_Severity_In;
  }

  /**
   * Getter method for known exploits
   *
   * @return string
   */
  public function get_Known_Exploits() {
    return $this->known_exploits;
  }

  /**
   * Setter method for known exploits
   *
   * @param string $str_Known_Exploits_In
   */
  public function set_Known_Exploits($str_Known_Exploits_In) {
    $this->known_exploits = $str_Known_Exploits_In;
  }

  /**
   * Getter function for linked CVE ID
   *
   * @return array
   */
  public function get_CVE() {
    return $this->cve;
  }

  /**
   * Setter function for linked CVE ID
   *
   * @param string $cve_in
   */
  public function add_CVE($cve_in) {
    if(!in_array($cve_in, $this->cve)) {
      $this->cve[] = $cve_in;
    }
  }

  /**
   * Getter method for iavm_references
   *
   * @return multitype:iavm_reference
   */
  public function get_References() {
    return $this->iavm_refs;
  }

  /**
   * Add new reference
   *
   * @param iavm_reference $ref
   */
  public function add_Reference($ref) {
    if(!in_array($ref, $this->iavm_refs)) {
      $this->iavm_refs[] = $ref;
    }
  }

  /**
   * Method to remove an IAVM reference
   *
   * @param iavm_reference $ref_in
   * @return boolean
   */
  public function remove_Reference($ref_in) {
    foreach($this->iavm_refs as $key => $ref) {
      if($ref_in->get_Title() == $ref->get_Title()) {
        unset($this->iavm_refs[$key]);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks to see if a reference is present in the array
   *
   * Returns true if it is, false otherwise
   *
   * @param iavm_reference $ref_in
   * @return boolean
   */
  public function reference_Exists($ref_in) {
    foreach($this->iavm_refs as $key => $ref) {
      if($ref_in == $ref) {
        return true;
      }
    }
    return false;
  }

  /**
   * Getter method for iavm bids
   *
   * @return multitype:iavm_bid
   */
  public function get_Bids() {
    return $this->iavm_bids;
  }

  /**
   * Add a BID to the array
   *
   * @param iavm_bid $bid_in
   */
  public function add_Bid($bid_in) {
    if(!$this->bid_Exists($bid_in)) {
      $this->iavm_bids[] = $bid_in;
    }
  }

  /**
   * Check to see if a BID is already in the array
   *
   * @param iavm_bid $bid_in
   *
   * @return boolean
   */
  public function bid_Exists($bid_in) {
    foreach($this->iavm_bids as $key => $bid) {
      if($bid->get_Bid() == $bid_in->get_Bid()) {
        return true;
      }
    }

    return false;
  }

  /**
   * Getter method for tech overview
   *
   * @return iavm_tech_overview
   */
  public function get_Tech_Overview() {
    return $this->iavm_tech_overview;
  }

  /**
   * Setter method for tech overview
   *
   * @param ivam_tech_overview $to
   */
  public function set_Tech_Overview($to) {
    $this->iavm_tech_overview = $to;
  }

  /**
   * Getter method for patches
   *
   * @return multitype:iavm_patch
   */
  public function get_Patches() {
    return $this->iavm_patches;
  }

  /**
   * Add new patch
   *
   * @param iavm_patch $patch
   */
  public function add_Patch($patch) {
    $this->iavm_patches[] = $patch;
  }

  /**
   * Method to remove patch from array
   *
   * Returns true if found and removed, otherwise false
   *
   * @param iavm_patch $patch_in
   * @return boolean
   */
  public function remove_Patch($patch_in) {
    foreach($this->iavm_patches as $key => $patch) {
      if($patch_in->get_Title() == $patch->get_Title()) {
        unset($this->iavm_patches[$key]);
        return true;
      }
    }
    return false;
  }

  /**
   * Method for checking to see if a patch exists
   *
   * Returns true if it exists, false otherwise
   *
   * @param iavm_patch $patch_In
   * @return boolean
   */
  public function patch_Exists($patch_In) {
    foreach($this->iavm_patches as $key => $patch) {
      if($patch_In == $patch) {
        return true;
      }
    }
    return false;
  }

  /**
   * Getter method for iavm mitigation strategy
   *
   * @return iavm_mitigation
   */
  public function get_Mitigation() {
    return $this->iavm_mitigation;
  }

  /**
   * Setter method for iavm mitigation
   *
   * @param iavm_mitigation $mit
   */
  public function set_Mitigation($mit) {
    $this->iavm_mitigation = $mit;
  }
}

/**
 * @author Ryan Prather
 */
class iavm_tech_overview {
  /**
   * Database ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Detailed text for the overview
   *
   * @var string
   */
  protected $details = '';

  /**
   * Constructor
   *
   * @param integer $id_in
   * @param string $details_in
   */
  public function __construct($id_in, $details_in) {
    $this->id = $id_in;
    $this->details = $details_in;
  }

  /**
   * Getter function for database ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter method for details text
   *
   * @return string
   */
  public function get_Details() {
    return $this->details;
  }

  /**
   * Setter method for details text
   *
   * @param string $str_Details_In
   */
  public function set_Details($str_Details_In) {
    $this->details = $str_Details_In;
  }
}

/**
 * @author Ryan Prather
 */
class iavm_reference {
  /**
   * Database ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Reference title
   *
   * @var string
   */
  protected $title = '';

  /**
   * Reference URL
   *
   * @var string
   */
  protected $url = '';

  /**
   * Constructor
   *
   * @param integer $id_in
   * @param string $title_in
   * @param string $url_in
   */
  public function __construct($id_in, $title_in, $url_in) {
    $this->id = $id_in;
    $this->title = $title_in;
    $this->url   = $url_in;
  }

  /**
   * Getter function for database ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter method for reference title
   *
   * @return string
   */
  public function get_Title() {
    return $this->title;
  }

  /**
   * Setter method for reference title
   *
   * @param string $str_Title_In
   */
  public function set_Title($str_Title_In) {
    $this->title = $str_Title_In;
  }

  /**
   * Getter method for reference URL
   *
   * @return string
   */
  public function get_URL() {
    return $this->url;
  }

  /**
   * Setter method for reference url
   *
   * @param string $str_URL_In
   */
  public function set_URL($str_URL_In) {
    $this->url = $str_URL_In;
  }
}

/**
 * @author Ryan Prather
 */
class iavm_patch {
  /**
   * Database ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Type of iavm patch
   *
   * @var string
   */
  protected $type = '';

  /**
   * Title of IAVM patch
   *
   * @var string
   */
  protected $title = '';

  /**
   * URL for the patch info
   *
   * @var string
   */
  protected $url = '';

  /**
   * Constructor
   *
   * @param integer $id_in
   * @param string $type_in
   * @param string $title_in
   * @param string $url_in
   */
  public function __construct($id_in, $type_in, $title_in, $url_in) {
    $this->id      = $id_in;
    $this->type    = $type_in;
    $this->title   = $title_in;
    $this->url     = $url_in;
  }

  /**
   * Getter function for database ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Getter method for patch type
   *
   * @return string
   */
  public function get_Type() {
    return $this->type;
  }

  /**
   * Setter method for patch type
   *
   * @param string $str_Type_In
   */
  public function set_Type($str_Type_In) {
    $this->type = $str_Type_In;
  }

  /**
   * Getter method for patch title
   *
   * @return string
   */
  public function get_Title() {
    return $this->title;
  }

  /**
   * Setter method for patch title
   *
   * @param string $str_Title_In
   */
  public function set_Title($str_Title_In) {
    $this->title = $str_Title_In;
  }

  /**
   * Getter method for patch URL
   *
   * @return string
   */
  public function get_URL() {
    return $this->url;
  }

  /**
   * Setter method for patch URL
   *
   * @param string $str_URL_In
   */
  public function set_URL($str_URL_In) {
    $this->url = $str_URL_In;
  }
}

/**
 * @author Ryan Prather
 */
class iavm_mitigation {
  /**
   * Header from mitigation strategy
   *
   * @var string
   */
  protected $header = '';

  /**
   * Mitigation text
   *
   * @var string
   */
  protected $text = '';

  /**
   * Constructor
   *
   * @param string $header_in
   * @param string $text_in
   */
  public function __construct($header_in, $text_in) {
    $this->header  = $header_in;
    $this->text    = $text_in;
  }

  /**
   * Getter method for header
   *
   * @return string
   */
  public function get_Header() {
    return $this->header;
  }

  /**
   * Setter method for header
   *
   * @param string $str_Header_In
   */
  public function set_Header($str_Header_In) {
    $this->header = $str_Header_In;
  }

  /**
   * Getter method for text
   *
   * @return string
   */
  public function get_Text() {
    return $this->text;
  }

  /**
   * Setter method for text
   *
   * @param string $str_Text_In
   */
  public function set_Text($str_Text_In) {
    $this->text = $str_Text_In;
  }
}

/**
 * @author Ryan Prather
 */
class iavm_bid {
  /**
   * Bugtraq ID
   *
   * @var integer
   */
  protected $bid = 0;

  /**
   *
   * @param integer $bid_in
   */
  public function __construct($bid_in) {
    $this->bid = $bid_in;
  }


  public function get_Bid() {
    return $this->bid;
  }
}
