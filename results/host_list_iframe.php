<?php
/**
 * File: index.php
 * Author: Paul Porter
 * Purpose Display the list of hosts for a particular scan
 * Created: Sep 20, 2013
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
 *  - Sep 23, 2013 - File created
 *  - Sep 1, 2016 - Copyright and file purpose updated
 *  - May 13, 2017 - Converted to use DataTables instead of tablesorter library
 *  - May 22, 2017 - Set page length to 25 records
 *  - Jan 16, 2018 - Added scanner error column to host list
 *  - Apr 19, 2018 - Updated 3rd party libraries
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$ste = filter_input(INPUT_GET, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$scan_id = filter_input(INPUT_GET, 'scan_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

$db = new db();
$scan = $db->get_ScanData($ste, $scan_id);
if (is_array($scan) && count($scan)) {
  $scan = $scan[0];
}
else {
  print "Invalid scan";
  die;
}

$counter = $scan->get_Host_List_Count();
$host_data = $scan->get_Host_List_Table();

// @TODO Add scanner error notes to tooltip popup for error
?>

<script src='/script/jquery-3.2.1.min.js'></script>
<script src='/script/datatables/DataTables-1.10.9/js/jquery.dataTables.min.js'></script>
<link rel="stylesheet" href="/script/datatables/DataTables-1.10.9/css/jquery.dataTables.min.css" />
<link rel='stylesheet' href='/script/jquery-ui/jquery-ui.min.css' />

<link rel="stylesheet" href="/style/5grid/core.css" />
<link rel="stylesheet" href="/style/5grid/core-desktop.css" />
<link rel="stylesheet" href="/style/5grid/core-1200px.css" />
<link rel="stylesheet" href="/style/5grid/core-noscript.css" />
<link rel="stylesheet" href="/style/style.css" />
<link rel="stylesheet" href="/style/style-desktop.css" />

<style>
  td {
    text-align: center;
  }

  h2 {
    text-align: center;
  }

  th {
    font-weight: normal;
  }

  .header {
    font-weight: bold;
  }

  #thead-host {
    background-color: #264C79;
    color: #fff;
    font-weight: normal;
  }

  .checklist_image {
      width: 32px;
      vertical-align: middle;
  }
</style>

<script type='text/javascript'>
  $(function () {
    $('#host_table').DataTable({
      'pageLength': 25
    });
  });
</script>

<h2>Host List</h2>
<table style="width: 100%">
  <tr>
    <td style="text-align: left">Total Number of Hosts: <?php print $counter; ?> </td>
    <td style="text-align: right">Total Number of Findings/Hosts: <?php print $host_data[0]; ?></td>
  </tr>
</table>
<table style="width: 100%" id='host_table' class='display compact'>
  <thead id="thead-host">
    <tr>
      <th>Host Number</th>
      <th>Host Name</th>
      <th>Findings</th>
      <th>IP Address</th>
      <th>Error</th>
    </tr>
  </thead>
  <tbody>
    <?php print $host_data[1]; ?>
  </tbody>
</table>





