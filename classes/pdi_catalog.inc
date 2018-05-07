<?php

/**
 * File: pdi_catalog.inc
 * Author: Ryan Prather
 * Purpose: Represents a PDI catalog item
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
 *  - Jun 27, 2017 - Added truncation for short title if longer than 255 characters
 *  - Oct 23, 2017 - Updated file header, added fix text and group title to class, and deleted SQL insert method
 */

/**
 * Represent a Potential Descrepancy Item (PDI)
 * @author Ryan Prather
 *
 */
class pdi {

  /**
   * ID
   *
   * @var integer
   */
  protected $id = 0;

  /**
   * Category level
   *
   * @var integer
   */
  protected $cat_lvl = 0;

  /**
   * Update DateTime
   *
   * @var DateTime
   */
  protected $update;

  /**
   * Check Contents
   *
   * @var string
   */
  protected $chk_content = '';

  /**
   * Fix Text
   *
   * @var string
   */
  protected $fix_text = null;

  /**
   * Group Title
   *
   * @var string
   */
  protected $group_title = null;

  /**
   * Short title
   *
   * @var string
   */
  protected $short_title = null;

  /**
   * Description
   *
   * @var string
   */
  protected $description = '';

  /**
   * Constructor
   *
   * @param integer $int_ID
   * @param integer:string $Cat_Lvl
   * @param string $dt_Update
   */
  public function __construct($int_ID, $Cat_Lvl, $dt_Update) {
    $this->id = $int_ID;
    if (is_string($dt_Update)) {
      $this->update = new DateTime($dt_Update);
    }
    elseif (is_a($dt_Update, 'DateTime')) {
      $this->update = $dt_Update;
    }
    else {
      $this->update = new DateTime();
    }

    if ($Cat_Lvl && $Cat_Lvl != '' && !is_null($Cat_Lvl)) {
      if (is_numeric($Cat_Lvl)) {
        $this->cat_lvl = $Cat_Lvl;
      }
      else {
        $this->cat_lvl = substr_count($Cat_Lvl, "I");
      }
    }
    else {
      $this->cat_lvl = 2;
      $this->description = "Defaulted Cat" . PHP_EOL . $this->description;
    }
  }

  /**
   * Getter function for PDI ID
   *
   * @return integer
   */
  public function get_ID() {
    return $this->id;
  }

  /**
   * Setter function for PDI ID
   *
   * @param integer $id
   */
  public function set_ID($id) {
    $this->id = $id;
  }

  /**
   * Getter function for category level
   *
   * @return integer
   */
  public function get_Category_Level() {
    return $this->cat_lvl;
  }

  /**
   * Gettr function for category level string
   *
   * @return string
   */
  public function get_Category_Level_String() {
    return implode("", array_fill(0, $this->cat_lvl, "I"));
  }

  /**
   * Setter function for category level
   *
   * @param integer:string $Cat_Lvl
   */
  public function set_Catetgory_Level($Cat_Lvl) {
    if (is_numeric($Cat_Lvl)) {
      $this->cat_lvl = $Cat_Lvl;
    }
    else {
      $this->cat_lvl = substr_count($Cat_Lvl, 'I');
    }
  }

  /**
   * Getter function for last update
   *
   * @return DateTime
   */
  public function get_Last_Update() {
    return $this->update;
  }

  /**
   * Setter function for last update
   *
   * @param string $dt_Update
   */
  public function set_Update($dt_Update) {
    $this->update = new DateTime($dt_Update);
  }

  /**
   * Getter function for check contents
   *
   * @return string
   */
  public function get_Check_Contents() {
    return $this->chk_content;
  }

  /**
   * Setter function for check contents
   *
   * @param string $str_Check_Content
   */
  public function set_Check_Contents($str_Check_Content) {
    $this->chk_content = $str_Check_Content;
  }

  /**
   * Getter function for the fix text
   *
   * @return string
   */
  public function get_Fix_Text() {
    return $this->fix_text;
  }

  /**
   * Setter function for the fix text
   *
   * @param string $fix_text_in
   */
  public function set_Fix_Text($fix_text_in) {
    if (is_array($fix_text_in) && count($fix_text_in) > 1) {
      $this->fix_text = implode("\n", $fix_text_in);
    }
    else {
      $this->fix_text = $fix_text_in;
    }
  }

  /**
   * Getter function for group title
   *
   * @return string
   */
  public function get_Group_Title() {
    return $this->group_title;
  }

  /**
   * Setter function for group title
   *
   * @param string $group_title_in
   */
  public function set_Group_Title($group_title_in) {
    $this->group_title = $group_title_in;
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
   * @param string $str_Short_Title
   */
  public function set_Short_Title($str_Short_Title) {
    $this->short_title = $str_Short_Title;
  }

  /**
   * Getter function for description
   *
   * @return string
   */
  public function get_Description() {
    return $this->description;
  }

  /**
   * Setter function for description
   *
   * @param string $str_Description
   */
  public function set_Description($str_Description) {
    $this->description = $str_Description;
  }

}
