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
 *  - Jun 2, 2018 - Added checkbox to allow for generation of new random SALT
 */
include_once 'config.inc';
include_once 'helper.inc';

$reset = (boolean) filter_input(INPUT_POST, 'reset', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);

if ($reset) {
    chdir(DOC_ROOT);
    $uname    = filter_input(INPUT_POST, 'uname', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    $pwd      = filter_input(INPUT_POST, 'pwd', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    $web_pwd  = filter_input(INPUT_POST, 'web_pwd', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    $new_salt = (boolean) filter_input(INPUT_POST, 'new-salt', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

    $db = new mysqli(DB_SERVER, $uname, $pwd, "mysql");
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

    if (!$db->real_query("SET PASSWORD FOR 'web'@'{$host}' = PASSWORD('{$web_pwd}')")) {
        include_once "header.inc";
        die("DB Password change unsuccessful, ceasing further operation" . PHP_EOL . $db->error);
    }

    /* ---------------------------------
     * 	CREATE DB PASSWORD FILE
     * --------------------------------- */
    $salt    = null;
    $enc_pwd = null;

    if ($new_salt) {
        $salt    = base64_encode(openssl_random_pseudo_bytes(32));
        $enc_pwd = my_encrypt($web_pwd, $salt);
    }
    else {
        $enc_pwd = my_encrypt($web_pwd);
    }

    if (!file_put_contents(DOC_ROOT . "/" . PWD_FILE, $enc_pwd)) {
        die("Failed to save password");
    }

    if ($salt) {
        print "Successfully updated the password, please copy the following text to the constant 'SALT' in the config.inc file, then the connection to the database will be restored<br />{$salt}<br />";
        print "<a href='/'>Home</a>";
    }
    else {
        print "Successfully updated the password, click <a href='/'>here</a> to continue";
    }
}
else {

    ?>

    <script src='/script/jquery-3.2.1.min.js' type='text/javascript'></script>
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
        New Random SALT: <input type='checkbox' name='new-salt' value='1' /><br />
        <br />
        New Web User Password: <input type="password" name="web_pwd" id="pwd" /><br />
        Confirm Password: <input type="password" name="conf_pwd" id="conf" onkeyup='javascript:chk_pwd();' /> <span id='msg'></span><br />

        <input type="submit" name="reset" value="Reset Password" />
    </form>

<?php } ?>