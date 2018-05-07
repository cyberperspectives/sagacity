<?php
/**
 * File: cpe.inc
 * Author: Ryan Prather
 * Purpose: Class to represent a Common Platform Enumeration (CPE)
 * Created: Mar 2, 2015
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Mar 2, 2015 - File created
 */

class cpe {

  public $part;


  public $vendor;


  public $product;


  public $version;


  public $update;


  public $edition;


  public $lang;


  public $sw_edition;


  public $tgt_sw;


  public $tgt_hw;


  public $other;

  /**
   * Constructor
   *
   * @param string $cpe_string
   */
  public function __construct($cpe_string) {
    $cpe_string = str_replace("_", " ", $cpe_string);
    $arr = explode(":", trim($cpe_string));
    if($arr[1] == '2.3') {
      $this->part       = $arr[2];
      $this->vendor     = $arr[3];
      $this->product    = $arr[4];
      $this->version    = $arr[5];
      $this->update     = $arr[6];
      $this->edition    = $arr[7] == '*' ? NULL : $arr[7];
      $this->lang       = $arr[8] == '*' ? NULL : $arr[8];
      $this->sw_edition = $arr[9] == '*' ? NULL : $arr[9];
      $this->tgt_sw     = $arr[10] == '*' ? NULL : $arr[10];
      $this->tgt_hw     = $arr[11] == '*' ? NULL : $arr[11];
      $this->other      = $arr[12] == '*' ? NULL : $arr[12];
    }
    else {
      $this->part       = $arr[1];
      $this->vendor     = $arr[2];
      $this->product    = $arr[3];
      $this->version    = isset($arr[4]) ? $arr[4] : NULL;
      $this->update     = isset($arr[5]) ? $arr[5] : NULL;
      $this->edition    = NULL;
      $this->lang       = NULL;
      $this->sw_edition = NULL;
      $this->tgt_sw     = NULL;
      $this->tgt_hw     = NULL;
      $this->other      = NULL;
    }
  }
}