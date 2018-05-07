<?php

/**
 * File: question.inc
 * Author: Ryan Prather
 * Purpose: Represent a interview question
 * Created: Aug 25, 2014
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
 *  - Aug 25, 2014 - File created
 *  - Sep 1, 2016 - Updated Copyright and comments
 */

/**
 * Represent a category interview question
 *
 * @author Ryan Prather
 */
class question {

  /**
   * The database ID of the question
   *
   * @var int
   */
  public $id = 0;

  /**
   * The category ID of the question
   *
   * @var int
   */
  public $cat = 0;

  /**
   * The unique key for the question
   *
   * @var string
   */
  public $key = '';

  /**
   * The question
   *
   * @var string
   */
  public $question = '';

  /**
   * The database ID of the answer
   *
   * @var int
   */
  public $answer = 0;

  /**
   * Constructor
   */
  public function __construct() {

  }

}
