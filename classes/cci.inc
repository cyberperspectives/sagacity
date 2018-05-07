<?php
/**
 * File: cci.inc
 * Author: Ryan Prather
 * Purpose: Represents a Control Correlation Identifier from NIST
 * Created: Sep 16, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 16, 2014 - File created
 */

/**
 * @author Ryan Prather
 */
class cci {
  /**
   * The CCI ID
   *
   * @var string
   */
  public $cci_id = '';

  /**
   * Control ID
   *
   * @var string
   */
  public $control_id = '';

  /**
   * Enhancement ID
   *
   * @var int
   */
  public $enh_id = '';

  /**
   * Definition of the CCI similar to a long description
   *
   * @var string
   */
  public $definition = '';

  /**
   * Implentation Guidance
   *
   * @var string
   */
  public $guidance = '';

  /**
   * Assessment procedures
   *
   * @var string
   */
  public $procedure = '';

  /**
   * Reference link from CCI to the NIST link
   *
   * @var array:cci_reference
   */
  public $refs = array();

  /**
   * Constructor
   */
  public function __construct() {}
}

/**
 * @author Ryan Prather
 */
class cci_reference {
  /**
   * Title of the reference
   *
   * @var string
   */
  public $title = '';

  /**
   * Release version
   *
   * @var int
   */
  public $ver = 0;

  /**
   * URL to the reference
   *
   * @var string
   */
  public $url = '';

  /**
   * Index
   *
   * @var string
   */
  public $index = '';

  /**
   * Constructor
   */
  public function __construct() {}
}