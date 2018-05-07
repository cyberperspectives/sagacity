<?php

/**
 * File: help.php
 * Author: Ryan Prather
 * Purpose: Perform context sensitive help
 * Created: Jan 30, 2014
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
 *  - Jan 30, 2014 - File created
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$db = new db();

print "<a id='top'></a>";

$topic = filter_input(INPUT_GET, 'topic', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$section = filter_input(INPUT_GET, 'section', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);

if ($topic) {
  $helps = $db->get_Help($topic);
  if (is_array($helps) && count($helps) && isset($helps['section'])) {
    $helps = [0 => $helps];
  }

  foreach ($helps as $key => $help) {
    print "<strong>";
    if (preg_match('/^[A-D]$/', $help['section'])) {
      print "Appendix ";
    }
    print "<span id='{$help['section']}'>{$help['section']}</span> - {$help['title']}</strong><br />";
    print "<div>" . $help['content'] . "</div><br /><a href='#top'>Top</a><br />";
  }
}
elseif (strlen($section)) {
  $help = $db->get_Help($section);
  print "<strong>{$help['section']} - {$help['title']}</strong><br />";
  print "<div>{$help['content']}</div>";
}
