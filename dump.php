<?php
/**
 * File: dump.php
 * Author: Ryan Prather
 * Purpose: Dump database so can start clean
 * Created: Sep 20, 2013
 *
 * Portions Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 20, 2013 - File created
 *  - Sep 01, 2016 - Copyright updated and converted to constants
 *  - Feb 21, 2017 - Added processing for view elements in db_schema.xml
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

if (isset($_REQUEST['pwd'])) {
  set_time_limit(0);
  $successful = true;
  // attempt to create a new database connection
  $conn = new mysqli(DB_SERVER, $_REQUEST['uname'], $_REQUEST['pwd']);
  $db = new db_helper($conn);

  $json = json_decode(file_get_contents(DOC_ROOT . "/db_schema.json"));
  $json->tables = array_reverse($json->tables);

  foreach ($json->tables as $table) {
    print "Dropping {$table->schema}.{$table->name}<br />";
    $db->drop($table->schema, $table->name);
  }

  print "<a href='/update.php'>Update</a>";
}
?>

<!DOCTYPE HTML>
<html>
  <head>
    <title>Dump Sagacity Database</title>
  </head>

  <body>
    <h1 style='color:#f00;'>DUMP DATABASE!</h1>
    <form method='post' action='#'>
      MySQL User Name: <input type='text' name='uname' /><br />
      Password: <input type='password' name='pwd' /><br />
      <input type='submit' name='submit' value='DUMP' />
    </form>
  </body>
</html>
