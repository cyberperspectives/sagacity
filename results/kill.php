<?php

/**
 * File: kill.php
 * Author: Ryan Prather
 * Purpose: Kill a running process
 * Created: May 19, 2014
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
 *  - May 19, 2014 - File created
 *  - Sep 1, 2016 - Copyright and function calls after class merger updated
 *  - May 31, 2017 - Fixed a couple bugs and enhanced functionality to mark scans as terminated instead of deleting them
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$db = new db();

$ste_id = filter_input(INPUT_GET, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$pid = filter_input(INPUT_GET, 'pid', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);

check_path(TMP . "/terminated");
$result = null;

try {
  if ($pid == '*') {
    $db->help->update("sagacity.scans", array('status' => 'TERMINATED'), array(
      array(
        'field' => 'ste_id',
        'op'    => '=',
        'value' => $ste_id
      ),
      array(
        'field'  => 'status',
        'op'     => '=',
        'value'  => 'RUNNING',
        'sql_op' => 'AND'
      )
    ));
  }
  elseif (!is_null($id) && is_numeric($id)) {
    $db->help->update("sagacity.scans", array("status" => 'TERMINATED'), array(
      array(
        'field' => 'ste_id',
        'op'    => '=',
        'value' => $ste_id
      ),
      array(
        'field'  => 'id',
        'op'     => '=',
        'value'  => $id,
        'sql_op' => 'AND'
      ),
      array(
        'field'  => 'status',
        'op'     => '=',
        'value'  => 'RUNNING',
        'sql_op' => 'AND'
      )
    ));
  }
  else {
    throw(new Exception("Invalid PID"));
  }

  $db->help->execute();
}
catch (Exception $e) {
  error_log($e->getTraceAsString() . PHP_EOL . print_r($result, true));
}

print "<script>window.close();</script>";
