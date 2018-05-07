<?php

/**
 * File: reset.php
 * Author: Ryan Prather
 * Purpose: Reset or change the password for the web mysql user
 * Created: Oct 16, 2014
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
 *  - Oct 16, 2014 - File created
 *  - Jun 3, 2015 - Copyright updated and added constants
 *  - Nov 7, 2016 - Fixed bug with resetting web user password, commented out calling Perl encrypt.pl script
 */
include_once 'config.inc';
include_once 'helper.inc';

if (isset($_REQUEST['reset'])) {
  chdir(DOC_ROOT);
  $db = new mysqli(DB_SERVER, $_REQUEST['uname'], $_REQUEST['pwd'], "mysql");
  if ($db->connect_error) {
    include_once "header.inc";
    die($db->connect_error);
  }

  if (in_array(DB_SERVER, array("localhost", "127.0.0.1"))) {
    $host = "localhost";
  }
  else {
    $host = '%';
  }

  if (!$db->real_query("SET PASSWORD FOR 'web'@'$host' = PASSWORD('" . $_REQUEST['web_pwd'] . "')")) {
    include_once "header.inc";
    die("DB Password change unsuccessful, ceasing further operation" . PHP_EOL . $db->error);
  }

  $pwd = $_REQUEST['web_pwd'];
  /* ---------------------------------
   * 	CREATE DB PASSWORD FILE
   * --------------------------------- */
  $enc_pwd = my_encrypt($pwd);

  if (!file_put_contents(DOC_ROOT . "/" . PWD_FILE, $enc_pwd)) {
    die("Failed to save password");
  }
  die($enc_pwd);

  print "Password change successful<br />";
  print "<a href='/'>Home</a>";
}
else {
  ?>

  <script src='/style/5grid/jquery-1.10.2.min.js' type='text/javascript'></script>
  <script type='text/javascript'>
    function chk_pwd() {
      if ($('#pwd').val() != $('#conf').val()) {
        $('#msg').text("Passwords do not match");
        $('#msg').css('color', 'red');
      }
      else {
        $('#msg').text("Passwords match");
        $('#msg').css('color', 'green');
      }
    }
  </script>

  <form method='post' action='reset.php'>
    MySQL Admin User Name: <input type="text" name="uname" /><br />
    Password: <input type="password" name="pwd" /><br />
    <br />
    New Web User Password: <input type="password" name="web_pwd" id="pwd" /><br />
    Confirm Password: <input type="password" name="conf_pwd" id="conf" onkeyup='javascript:chk_pwd();' /> <span id='msg'></span><br />

    <input type="submit" name="reset" value="Reset Password" />
  </form>

<?php } ?>