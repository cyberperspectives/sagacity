<?php

/**
 * File: index.php
 * Author: Ryan Prather
 * Purpose: Index home page, redirects to ST&E Ops page
 * Created: Sep 11, 2013
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 11, 2013 - File created
 */
if (isset($_REQUEST['phpinfo'])) {
  print phpinfo();
  die;
}

$match = [];

$config = file_get_contents("config.inc", FILE_USE_INCLUDE_PATH);
if (preg_match("/@new/", $config)) {
  header("Location: /setup.php");
  die;
}
elseif (preg_match("/@step(\d)/", $config, $match)) {
  header("Location: /setup.php?step={$match[1]}");
  die;
}

header("Location: /ste/");
