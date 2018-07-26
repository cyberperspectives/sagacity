<?php
/**
 * File: menu.inc
 * Author: Ryan Prather
 * Purpose: Display the top nav menu
 * Created: Sep 11, 2013
 *
 * Portions Copyright 2016-2018: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 11, 2013 - File created
 *  - Sep 1, 2016 - Copyright and whole menu updated
 *  - Oct 10, 2016 - Removed "Upload Progress" menu item because it's functionality was merged in withe results/index.php
 *  - Oct 24, 2016 - Renamed "Mission Systems" to "Systems"
 * 					 Renamed "Site" to "Sites"
 * 					 Added "Target Filter" to top nav
 *  - Mar 8, 2017 - Formatting and added check for presence of /proc directory before displaying Procedural Operations menu
 *  - Apr 5, 2017 - Moved montre function, CSS, and related content having to do with menu code
 *  - Jan 10, 2018 - Added link to /ste/stats.php
 */
$results = '';
$data = '';
$ops = '';
$report = '';

$script_name = filter_input(INPUT_SERVER, 'SCRIPT_NAME', FILTER_SANITIZE_STRING);

if (preg_match('/ste|proc/', $script_name)) {
  $ops = " class='active'";
}
elseif (preg_match('/results/', $script_name)) {
  $results = " class='active'";
}
elseif (preg_match('/data/', $script_name)) {
  $data = " class='active'";
}
elseif (preg_match('/report/', $script_name)) {
  $report = " class='active'";
}
?>

<script type='text/javascript'>
  $(function () {
    window.onload = montre;
  });

  function montre(id) {
    $("dd[id^='smenu']").hide();
    if (id && typeof id == 'string') {
      $('#' + id).show();
    }
  }
</script>

<style type="text/css">
  dl, dt, dd, ul, li {
    margin: 0;
    padding: 0;
    list-style-type: none;
    z-index: 100;
  }
  #menu {
    width: 25px;
    display: table-cell;
  }

  #menu dt {
    cursor: pointer;
    text-align: center;
    font-weight: bold;
  }

  #menu dd {
    position: fixed;
    z-index: 100;
    width: 10em;
    background: #B4B2B2;
    border: 1px solid gray;
  }

  #menu ul {
    padding: 2px;
  }
  #menu li {
    text-align: center;
    font-size: 85%;
    height: 18px;
    line-height: 18px;
  }
  #menu li a, #menu dt a {
    color: #000;
    text-decoration: none;
    display: block;
  }

  #menu li a:hover {
    text-decoration: underline;
  }
</style>

<ul id="menu-bar">
  <li<?php print $ops; ?>><a href="javascript:void(0);">Operations</a>
    <ul>
      <li><a href="/ste">ST&amp;E Operations</a></li>
      <li><a href='/ste/stats.php'>Stats</a></li>
      <?php if (file_exists(DOC_ROOT . "/proc")) { ?>
        <li><a href = "/proc">Procedural Operations</a></li>
      <?php } ?>
    </ul>
  </li>
  <li<?php print $results; ?>><a href="javascript:void(0);">Scans</a>
    <ul>
      <li><a href="/results">Results</a></li>
      <li><a href="/results/?add_scan=1">Add Scan</a></li>
    </ul>
  </li>
  <?php if (file_exists(DOC_ROOT . "/report")) { ?>
    <li<?php print $report; ?>><a href="javascript:void(0);">Report</a>
      <ul>
        <li><a href="/report/sanity.php?step=1">Sanity Check</a></li>
        <li><a href="/report/create.php">Create Risk Assessment</a></li>
      </ul>
    </li>
  <?php } ?>
  <li<?php print $data; ?>><a href="javascript:void(0);">Management</a>
    <ul>
      <li><a href="/data/?p=MSMgmt">Systems</a></li>
      <li><a href="/data/?p=SiteMgmt">Sites</a></li>
      <li><a href="/data/?p=STEMgmt">ST&amp;E</a></li>
      <li><a href="/data/?p=CatMgmt">Catalog</a></li>
      <li><a href="/data/?p=Settings">Settings</a></li>
      <li><a href="/data/?p=Search">Search</a></li>
      <li><a href="/data/?p=TgtSearch">Target Search</a></li>
    </ul>
  </li>
  <li>
    <form method="post" action="/data/?p=Search" target="_blank" style="display:inline-block;">
      <input type="text" style="vertical-align:text-bottom;" name="q" placeholder="Search..." />
    </form>
  </li>
</ul>
