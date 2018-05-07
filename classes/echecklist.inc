<?php
/**
 * File: echecklist.inc
 * Author: Ryan Prather
 * Purpose: Represents and entry in an eChecklist
 * Created: Oct 14, 2013
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Oct 14, 2013 - File created
 */

/**
 * Represents an echecklist object
 *
 * @author Ryan Prather
 */
class echecklist {
  /**
   * Defines what the first column is that has a host name in it (0-based)
   *
   * @var integer
   */
  const HOST_COL_START = 5;

  /**
   * PDI ID
   *
   * @var integer
   */
  protected $pdi_id = 0;

  /**
   * STIG ID
   *
   * @var string
   */
  protected $stig = '';

  /**
   * VMS ID (GoldDisk)
   *
   * @var string
   */
  protected $vms = '';

  /**
   * Category level (1-3)
   *
   * @var integer
   */
  protected $cat = 0;

  /**
   * IA Control
   *
   * @var string
   */
  protected $ia_controls = array();

  /**
   * Short title
   *
   * @var string
   */
  protected $short_title = '';

  /**
   * Array of target statuses
   *
   * @var array:string
   */
  protected $tgt_status = array ();

  /**
   * Notes
   *
   * @var string
   */
  protected $notes = '';

  /**
   * Check contents
   *
   * @var string
   */
  protected $check_contents = '';

  /**
   * Missing PDI
   *
   * @var string
   */
  protected $missing_pdi = '';

  /**
   * Constructor
   *
   * @param string $str_STIG_ID
   * @param string $str_VMS_ID
   * @param integer $int_Cat_Level
   * @param string $str_IA_Controls
   * @param string $str_Short_Title
   * @param string $str_Targets
   * @param string $str_Notes
   * @param string $str_Check_Contents
   * @param string $str_Missing_PDI
   */
  public function __construct($str_STIG_ID, $str_VMS_ID, $int_Cat_Level, $str_IA_Controls, $str_Short_Title, $str_Targets, $str_Notes, $str_Check_Contents, $str_Missing_PDI) {
    $this->stig = $str_STIG_ID;
    $this->vms = $str_VMS_ID;
    if(is_numeric($int_Cat_Level) && $int_Cat_Level > 0) {
      $this->cat = $int_Cat_Level;
    }
    elseif($int_Cat_Level == 0) {
      $this->cat = 2;
    }
    else {
      $this->cat = substr_count($int_Cat_Level, "I");
    }
    $this->ia_controls = $str_IA_Controls;
    $this->short_title = $str_Short_Title;
    $this->notes = $str_Notes;
    $this->check_contents = $str_Check_Contents;
    $this->missing_pdi = $str_Missing_PDI;

    if(substr_count($str_Targets, ",") > 0) {
      $hosts = explode(",", $str_Targets);
      foreach($hosts as $host) {
        $id_status = explode("=>", $host);
        $this->tgt_status[$id_status[0]] = $id_status[1];
      }
    }
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
   * @param integer $pdi_id_in
   */
  public function set_PDI_ID($pdi_id_in) {
    $this->pdi_id = $pdi_id_in;
  }

  /**
   * Getter function for STIG ID
   *
   * @return string
   */
  public function get_STIG_ID() {
    return $this->stig;
  }

  /**
   * Getter function for VMS ID
   *
   * @return string
   */
  public function get_VMS_ID() {
    return $this->vms;
  }

  /**
   * Getter function for category level
   *
   * @return integer
   */
  public function get_Cat_Level() {
    return $this->cat;
  }

  /**
   * Getter function for string category level
   *
   * @return string
   */
  public function get_Cat_Level_String() {
    if($this->cat) {
      return implode("", array_fill(0, $this->cat, "I"));
    }
    return 'II';
  }

  /**
   * Setter function for the category level
   *
   * @param mixed $cat_lvl_in
   */
  public function set_Cat_Level($cat_lvl_in) {
    if(is_numeric($cat_lvl_in)) {
      $this->cat = $cat_lvl_in;
    }
    elseif(preg_match("/I/i", $cat_lvl_in)) {
      $this->cat = substr_count($cat_lvl_in, "I");
    }
  }

  /**
   * Getter function for IA control
   *
   * @return array
   */
  public function get_IA_Controls() {
    return $this->ia_controls;
  }

  /**
   *
   * @return string
   */
  public function get_IA_Controls_String() {
    if(is_string($this->ia_controls)) {
      return $this->ia_controls;
    }
    elseif(is_array($this->ia_controls)) {
      return implode(" ", $this->ia_controls);
    }
  }

  /**
   * Setter function for IA controls
   *
   * @param mixed $ia_controls_in
   */
  public function set_IA_Controls($ia_controls_in) {
    if(is_array($ia_controls_in)) {
      $this->ia_controls = $ia_controls_in;
    }
    elseif(is_string($ia_controls_in)) {
      $this->ia_controls = explode(" ", $ia_controls_in);
    }
  }

  /**
   * Getter function for short title
   *
   * @return string
   */
  public function get_Short_Title() {
    return $this->short_title;
  }

  /**
   * Setter function for short title
   *
   * @param string $short_title_in
   */
  public function set_Short_Title($short_title_in) {
    $this->short_title = $short_title_in;
  }

  /**
   * Getter function for target status array
   *
   * @return array:string
   */
  public function get_Targets() {
    return $this->tgt_status;
  }

  /**
   * Add function for target status
   *
   * @param integer $int_Target_ID
   * @param string $str_Status
   */
  public function add_Target($int_Target_ID, $str_Status) {
    $this->tgt_status[$int_Target_ID] = $str_Status;
  }

  /**
   * Setter function to set the status of an associated target
   *
   * @param integer $int_Target_ID
   * @param string $str_Status
   */
  public function set_Target_Status($int_Target_ID, $str_Status) {
    $this->tgt_status[$int_Target_ID] = $str_Status;
  }

  /**
   * Getter function for notes
   *
   * @return string
   */
  public function get_Notes() {
    return $this->notes;
  }

  /**
   * Setter function for notes
   *
   * @param string $notes
   */
  public function set_Notes($notes) {
    $this->notes = $notes;
  }

  /**
   * Append notes
   *
   * @param string $notes
   */
  public function append_Notes($notes) {
    $this->notes .= $notes;
  }

  /**
   * Getter function for check contents
   *
   * @return string
   */
  public function get_Check_Contents() {
    return $this->check_contents;
  }

  /**
   * Setter function for check contents
   *
   * @param string $chk_contents_in
   */
  public function set_Check_Contents($chk_contents_in) {
    $this->check_contents = $chk_contents_in;
  }

  /**
   * Getter function for missing PDI
   *
   * @return string
   */
  public function get_Missing_PDI() {
    return $this->missing_pdi;
  }

  /**
   * Setter function for missing PDI
   *
   * @param string $missing_pdi_in
   */
  public function set_Missing_PDI($missing_pdi_in) {
    $this->missing_pdi = $missing_pdi_in;
  }

  /**
   * Getter function for preformated table row
   *
   * @return string
   */
  public function get_Table_Row() {
    $cat_string = $this->get_Cat_Level_String();

    $ret = "<tr>" .
      "<td>$this->stig</td>" .
      "<td>$this->vms</td>" .
      "<td class='cat_" . $cat_string . "'>" . $cat_string . "</td>" .
      "<td>$this->ia_controls</td>" .
      "<td>$this->short_title</td>";

    foreach($this->tgt_status as $key => $val) {
      $class = str_replace(' ', '_', strtolower($val));
      $ret .= "<td class='$key $class cat_" . $this->cat . "'>$val</td>";
    }

    $ret .= "<td>".htmlentities($this->notes)."</td>" .
      "<td>$this->check_contents</td>" .
      "<td>$this->missing_pdi</td>" .
    "</tr>";

    return $ret;
  }

}
