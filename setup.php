<?php
/**
 * File: setup.php
 * Author: Ryan Prather <ryan.prather@cyberperspectives.com>
 * Purpose: Allow setup process for new installations
 * Created: Nov 28, 2017
 *
 * Copyright 2017: Cyber Perspective, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Nov 28, 2017 - File created
 *  - Dec 27, 2017 - Added check for local mysql server and empty root password, updated include path to display root path
 *  - Apr 29, 2018 - Updated 3rd party libraries
 *  - May 10, 2018 - Added root confirmation password validation (bug #412)
 */
set_time_limit(0);
include_once 'helper.inc';

/**
 *  check for PHP settings
 *  1. is openssl installed and running?
 *  2. is mysqli installed and running?
 *  3. is ZipArchive class installed?
 *  4. is the request_order set correctly? GPCS?
 *  5. is root, inc, and classes folders in include_path
 */
$fail   = false;
$config = file_get_contents(dirname(__FILE__) . "/config.inc");
if (version_compare(PHP_VERSION, '7.1') < 0) {
    print "The minimum version of PHP necessary is 7.1, please upgrade to continue<br />";
    $fail = true;
}

if (!is_writable(dirname(__FILE__))) {
    print <<<EOO
The Apache user requires write access to all directories in the document root, please make sure that all permissions are as follows:

Directories = rwx
Files = rw

On *nix: find ./ -type d -exec chmod 775 {} \; && find ./ -type f -exec chmod 665 {} \;
EOO;

    die();
}

if (!is_writable(dirname(__FILE__) . "/config.inc")) {
    die("Sagacity needs write access to the config.inc file in the document root");
}

if(!is_writable(dirname(__FILE__) . "/inc")) {
	die("Sagacity needs write access to the /inc directory to create the encrypted password file");
}

if(!file_exists(dirname(__FILE__) . "/logs")) {
	mkdir(dirname(__FILE__) . "/logs");
}

if (!function_exists('openssl_encrypt')) {
    print <<<EOO
The PHP OpenSSL module is not install or enabled.<br />
Visit <a href='/?phpinfo=1'>PHPInfo</a> to double-check this.  If you know it's installed, restart Apache and see if that works.<br /><br />
EOO;
    $fail = true;
}
else {
    $algorithms = ["AES-256-CBC-HMAC-SHA256", "AES-256-CBC-HMAC-SHA1", "AES-256-CBC"];
    if (in_array($algorithms[0], openssl_get_cipher_methods())) {
        $idx = 0;
    }
    elseif (in_array($algorithms[1], openssl_get_cipher_methods())) {
        $idx = 1;
    }
    elseif (in_array($algorithms[2], openssl_get_cipher_methods())) {
        $idx = 2;
    }
    else {
        print <<<EOO
The needed encryption algorithm is not available please install one of the following:

EOO;

        print implode("<br />", $algorithms);

        $fail = true;
    }

    if (!$fail) {
        my_str_replace("{ALGORITHM}", $algorithms[$idx], $config);

        $salt = base64_encode(openssl_random_pseudo_bytes(32));

        my_str_replace("{SALT}", $salt, $config);

        file_put_contents(dirname(__FILE__) . "/config.inc", $config);
    }
}

if (!class_exists('mysqli')) {
    print <<<EOO
The PHP mysqli module is not installed or enabled.<br />
Visit <a href='/?phpinfo=1'>PHPInfo</a> to double-check this.  If you know it's installed, retstart Apache and try again<br /><br />
EOO;
    $fail = true;
}

if (!class_exists('ZipArchive')) {
    print <<<EOO
The PHP ZipArchive moduel is not installed or enabled.<br />
Visit <a href='/?phpinfo=1'>PHPInfo</a> to double-check this.<br /><br />
EOO;
    $fail = true;
}

if (strtolower(substr(PHP_OS, 0, 3)) == "win" && !class_exists("COM")) {
    print <<<EOO
The Component Object Model (COM) class is not available.  Please make sure it is installed and enabled<br />
Visit <a href='http://php.net/manual/en/book.com.php'>http://php.net/manual/en/book.com.php</a> for more info
EOO;
    $fail = true;
}
elseif (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
    try {
        $com = new COM("WScript.Shell");
    }
    catch (Exception $e) {
        print <<<EOO
The Component Object Model (COM) class does not seem to be available
EOO;
        $fail = true;
    }
}

$ro = ini_get('request_order');
if ($ro != 'GPCS' && $ro != 'GPC') {
    print <<<EOO
The request_order directive in php.ini is not set correctly.  It needs to be either GPC or GPCS, it is currently $ro.<br />
Open the php.ini file, search for request_order, and change it to either GPC or GPCS. After it's saved, you'll need to restart Apache<br /><br />
EOO;
    $fail = true;
}

if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
    $delim = ';';
}
else {
    $delim = ':';
}
$inc_path = explode($delim, ini_get('include_path'));
$doc_root = realpath(dirname(__FILE__));

$classes = realpath("{$doc_root}/classes");
$inc     = realpath("{$doc_root}/inc");
$root    = realpath(dirname(__FILE__));

if (!in_array($inc, $inc_path) || !in_array($classes, $inc_path) || !in_array($root, $inc_path)) {
    print <<<EOO
The include_path directive in php.ini does not include the required paths.<br />
Open the php.ini file, search for include_path (and make sure that the one for your OS) includes $root, $inc, &amp; $classes<br />
Current include_path:
EOO;
    print ini_get('include_path') . "<br />";

    $fail = true;
}

$match     = [];
$mem_limit = return_bytes(ini_get("memory_limit"));
$gig       = return_bytes('1G');
if ($mem_limit < $gig) {
    print <<<EOO
Sagacity does many data intensive actions, so we recommend a memory_limit of 1G.  $mem_limit bytes is the current setting.<br />
To change this, open the php.ini file and look for 'memory_limit' and set to at least 1G<br />
EOO;
}

if (!ini_get("file_uploads")) {
    print "File uploads are currently turned off by the file_uploads directive in php.ini.  Please turn them back on if you wish to upload files through the user interfaces<br />";
}
else {
    $upload_file_max = return_bytes(ini_get('upload_max_filesize'));
    $post_max_size   = return_bytes(ini_get('post_max_size'));

    if ($upload_file_max != $post_max_size) {
        print <<<EOO
Upload file max size ($upload_file_max bytes) and post max size ($post_max_size bytes) do not match.  The smaller will be used to limit uploaded file sizes.<br />
To change this, open the php.ini file and change 'upload_max_filesize' and 'post_max_size'<br />
EOO;
    }
}

if ($fail) {
    die;
}

$is_online = ping("cyberperspectives.com");

$step = filter_input(INPUT_GET, 'step', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

$blank_root = false;
$mysql_host = '';
mysqli_report(MYSQLI_REPORT_STRICT);
try {
    $db = new mysqli("localhost", "root", "");
    if (!$db->connect_errno) {
        $blank_root = true;
        $mysql_host = 'localhost';
    }
}
catch (Exception $e) {

}

if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
    $mysql_host = 'localhost';
}

?>

<!DOCTYPE HTML>
<html>
    <head>
        <title>Sagacity Setup</title>

        <link href='/style/fonts/fonts.css' rel='stylesheet' type='text/css' />
        <!--[if IE 9]><link rel="stylesheet" href="style/style-ie9.css" /><![endif]-->
        <link href='/script/jquery-ui/jquery-ui.min.css' rel='stylesheet' type='text/css' />

        <script src="/script/jquery-3.2.1.min.js"></script>
        <script src="/style/5grid/jquery.browser.min.js"></script>
        <script type="text/javascript" src="/script/jquery-ui/jquery-ui.min.js"></script>
        <script
        src="/style/5grid/init.js?use=mobile,desktop,1000px&amp;mobileUI=1&amp;mobileUI.theme=none"></script>
        <script type="text/javascript" src="/script/default.js"></script>
        <script type="text/javascript" src="/script/spin/spin.min.js"></script>

        <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">

        <link rel="apple-touch-icon" sizes="57x57" href="/apple-touch-icon-57x57.png">
        <link rel="apple-touch-icon" sizes="114x114" href="/apple-touch-icon-114x114.png">
        <link rel="apple-touch-icon" sizes="72x72" href="/apple-touch-icon-72x72.png">
        <link rel="apple-touch-icon" sizes="144x144" href="/apple-touch-icon-144x144.png">
        <link rel="apple-touch-icon" sizes="60x60" href="/apple-touch-icon-60x60.png">
        <link rel="apple-touch-icon" sizes="120x120" href="/apple-touch-icon-120x120.png">
        <link rel="apple-touch-icon" sizes="76x76" href="/apple-touch-icon-76x76.png">
        <link rel="apple-touch-icon" sizes="152x152" href="/apple-touch-icon-152x152.png">
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon-180x180.png">
        <link rel="icon" type="image/png" href="/favicon-192x192.png" sizes="192x192">
        <link rel="icon" type="image/png" href="/favicon-160x160.png" sizes="160x160">
        <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96">
        <link rel="icon" type="image/png" href="/favicon-16x16.png" sizes="16x16">
        <link rel="icon" type="image/png" href="/favicon-32x32.png" sizes="32x32">
        <meta name="msapplication-TileColor" content="#da532c">
        <meta name="msapplication-TileImage" content="/mstile-144x144.png">

        <style type='text/css'>
            #msg {
                display: none;
            }

            .err {
                color: white;
                background-color: red;
            }

            .msg {
                color: white;
                background-color: green;
            }

            #pwd-msg, #root-pwd-msg {
                display: none;
                width: 25px;
            }

            #root-conf {
                display: none;
            }

            .buttons {
                text-align: right;
            }

            .label {
                width: 250px;
                display: inline-block;
            }

            .left {
                width: 49%;
                display: inline-block;
                vertical-align: top;
            }

            .right {
                width: 49%;
                display: inline-block;
            }

            .setup-header, .buttons {
                width: 49%;
                display: inline-block;
            }
        </style>

        <script type="text/javascript">
            var current_step = 0;
            $(function () {
              $('#tabs').tabs({
                disabled: [1, 2]
              });
              $('#derived-on,#declassify-on').datepicker({dateFormat: "yy-mm-dd"});
              $('.next').click(next_step);
              $('.back').click(prev_step);

<?php
if ($blank_root) {
    print "alert('System has detected your root MySQL password is blank. Please enter the password you want in the blank and the confirmation and we can set the password');";
    print "$('#root-conf').show();";
}

if ($step !== null && $step > 0) {
    switch ($step) {
        case 2:
            print <<<EOL
            $('#tabs').tabs('enable', 2)
                    .tabs('option', 'active', 2);
            current_step = 2;

EOL;
            break;
        case 1:
            print <<<EOL
            $('#tabs').tabs('enable', 1)
                    .tabs('option', 'active', 1);
            current_step = 1;

EOL;
            break;
    }

    switch ($step) {
        case 2:
            print "        $('#tabs').tabs('disable', 1);" . PHP_EOL;
        case 1:
            print "        $('#tabs').tabs('disable', 0);" . PHP_EOL;
            print "        setTimeout(function(){enable_next(current_step);}, 3000);" . PHP_EOL;
    }
}

?>
            });
            function next_step() {
              var params;
              if (current_step == 0) {
                if ($('#web-pwd').val() != $('#conf').val()) {
                  display_msg("Web passwords don't match");
                  $('#web-pwd').focus();
                  return;
                }
                if ($('#root-conf').is(":visible") && $('#root-pwd').val() != $('#root-conf').val()) {
                  display_msg("Root passwords don't match");
                  $('#root-pwd').focus();
                  return;
                }
                var action = null;
                if ($('#do').is(":checked")) {
                  action = 'do';
                }
                else if ($('#po').is(":checked")) {
                  action = 'po';
                }
                params = {
                  'step': current_step,
                  'doc-root': $('#doc-root').val(),
                  'pwd-file': $('#pwd-file').val(),
                  'tmp-path': $('#tmp-path').val(),
                  'log-path': $('#log-path').val(),
                  'log-level': $('#log-level').val(),
                  'db-server': $('#db-server').val(),
                  'root-uname': $('#root-uname').val(),
                  'root-pwd': $('#root-pwd').val(),
                  'conf-root-pwd': $('#root-conf').val(),
                  'web-pwd': $('#web-pwd').val(),
                  'sample-data': ($('#sample-data').is(':checked') ? '1' : '0'),
                  'cpe': ($('#cpe').is(":checked") ? '1' : '0'),
                  'cve': ($('#cve').is(":checked") ? '1' : '0'),
                  'stig': ($('#stig').is(":checked") ? '1' : '0'),
                  'action': action
                };
              }
              else if (current_step == 1) {
                params = {
                  'step': current_step,
                  'company': $('#comp-name').val(),
                  'comp-add': $('#comp-add').val(),
                  'last-modified': $('#last-modified-by').val(),
                  'creator': $('#creator').val(),
                  'system-class': $('#sys-class').val(),
                  'classified-by': $('#classified-by').val(),
                  'scg': $('#derived-by').val(),
                  'derived-on': $('#derived-on').val(),
                  'declassify-on': $('#declassify-on').val()
                };
              }
              else if (current_step == 2) {
                params = {
                  'step': current_step,
                  'flatten': ($('#flatten').is(":checked") ? "1" : '0'),
                  'wrap-text': ($('#wrap-text').is(":checked") ? "1" : "0"),
                  'notifications': ($('#notifications').is(":checked") ? '1' : '0'),
                  'port-limit': $('#port-limit').val(),
                  'max-results': $('#max-results').val(),
                  'output-format': $('#output-format').val()
                };
              }

              $.ajax('/exec/installer.php', {
                data: params,
                beforeSend: function () {
                  display_msg('Processing', 'msg');
                },
                success: function (data) {
                  if (data.error) {
                    display_msg(data.error + "<br />Go back to the previous step and fix the error", 'err');
                  }
                  else if (data.success) {
                    if (current_step > 2) {
                      location.href = '/ste/';
                    }
                    if (data.msg) {
                      display_msg(data.msg, 'msg', 10000);
                    }
                    else {
                      display_msg('Step Completed', 'msg');
                    }
                  }
                },
                error: function (xhr, status, error) {
                  console.error(error);
                  display_msg(error, 'err');
                },
                dataType: 'json',
                method: 'post'
              });
              current_step++;
              $('#tabs').tabs('enable', current_step)
                      .tabs('option', 'active', current_step)
                      .tabs('disable', current_step - 1);
              setTimeout(function () {
                enable_next(current_step);
              }, 3000);
            }

            function display_msg(msg, err_class, delay = 3000) {
              $('#msg').removeClass('msg err')
                      .addClass(err_class)
                      .html(msg)
                      .slideDown();
              setTimeout(function () {
                $('#msg').slideUp();
              }, delay);
            }

            function enable_next(step) {
              if (step == 1) {
                $('#company').find('.next')
                        .removeClass('button-delete')
                        .addClass('button')
                        .prop('disabled', false);
              }
              else if (step == 2) {
                $('#options').find('.next')
                        .removeClass('button-delete')
                        .addClass('button')
                        .prop('disabled', false);
              }
            }

            function prev_step() {
              current_step--;
              $('#tabs').tabs('enable', current_step);
              $('#tabs').tabs('option', 'active', current_step);
              $('#tabs').tabs('disable', current_step + 1);
            }

            function chk_pwd() {
              if ($('#web-pwd').val() != $('#conf').val()) {
                $('#pwd-msg').attr('src', "/img/X.png");
              }
              else {
                $('#pwd-msg').attr('src', "/img/ok.png");
              }
              $('#pwd-msg').show();
            }

            function chk_root_pwd() {
              if ($('#root-conf').is(":visible")) {
                if ($('#root-pwd').val() != $('#root-conf').val()) {
                  $('#root-pwd-msg').attr('src', '/img/X.png');
                }
                else {
                  $('#root-pwd-msg').attr('src', '/img/ok.png');
                }
                $('#root-pwd-msg').show();
              }
            }
        </script>
    </head>

    <body>
        <div id="header-wrapper" style="height:125px;">
            <header id="header" class="5grid-layout">
                <div class="row">
                    <div class="12u" style="text-align:center;">
                        <!-- Logo -->
                        <span class="mobileUI-site-name">
                            <img src='/img/Sagacity-Logo.png' style='width:365px;' />
                        </span>
                    </div>
                </div>
            </header>
        </div>
        <div style="width:1200px;margin:auto;">
            <?php
            print "Maximum file upload size is currently set to " . ini_get("upload_max_filesize") . "B<br />";
            print "Your current timezone is set to " . ini_get("date.timezone") . "<br />";

            ?>

            <div id='msg'></div>

            <div id='tabs' style='height:450px;'>
                <ul>
                    <li><a href='#database'>Database</a></li>
                    <li><a href='#company'>Company</a></li>
                    <li><a href='#options'>Options</a></li>
                </ul>

                <div id='database'>
                    <div class='setup-header'>
                        <h2>Database Configuration</h2>
                    </div>
                    <div class="buttons">
                        <input type='button' class='button' value='Adv Web Settings' onclick="$('#advanced').slideToggle();" />&nbsp;&nbsp;
                        <input type='button' class='button next' value='Next' />
                    </div>

                    <div class='left'>
                        <label class='label' for='db_server'>Database Server:</label>

                        <input type='text' id="db-server" placeholder="Hostname or IP" value='<?php print $mysql_host; ?>' title='Database server DNS name or IP' /><br />

                        <span class='label'>
                            <input type='text' id='root-uname' placeholder='Root username' value='root' />
                        </span>
                        <input type='password' id='root-pwd' placeholder='Root password' /><br />
                        <label class='label'>&nbsp;</label>
                        <input type='password' id='root-conf' onkeyup='javascript:chk_root_pwd();' placeholder='Confirm root password' /> <img id='root-pwd-msg' /><br />

                        <label class='label' for='pwd'>Web user password:</label>
                        <input type='password' id='web-pwd' /><br />

                        <label class='label' for='conf'>Confirm password:</label>
                        <input type='password' id='conf' onkeyup='javascript:chk_pwd();' /> <img id='pwd-msg'/><br />

                        <label class='label' for='sample-data'>Add Sample Data:</label>
                        <input type='checkbox' id='sample-data' title='Add sample data to database' /><br />
                    </div>

                    <div class='right'>
                        <label for='cpe' class='label'>Load CPE's:</label>
                        <input type='checkbox' id='cpe' checked title="Do you want to load CPE's upon completion?" /><br />

                        <label for='cve' class='label'>Load CVE's:</label>
                        <input type='checkbox' id='cve' checked title="Do you want to laod CVE's upon completion?" /><br />

                        <label for='stig' class='label'>Load STIG's:</label>
                        <input type='checkbox' id='stig' checked title="Do you want to load STIG's upon completion?" /><br />

                        <?php if ($is_online) { ?>
                            <label for='dp' class='label'>Online:</label>
                            <input type='radio' id='dp' name='action' value='dp' checked /><br />

                            <label for='do' class='label'>Download only:</label>
                            <input type='radio' id='do' name='action' value='do' /><br />
                        <?php } ?>

                        <label for='po' class='label'>Offline:</label>
                        <input type='radio' id='po' name='action' value='po' />&nbsp;&nbsp;
                    </div>

                    <div id='advanced' style='display:none;margin-top:15px;'>
                        <div class="left">
                            <label class='label'>Web Root:</label>
                            <input type='text' id='doc-root' value='<?php print realpath(getcwd()); ?>' title='Absolute path of the document root' /><br />

                            <label class='label'>Password File:</label>
                            <input type='text' id='pwd-file' value='inc/passwd' title='Relative path to the encrypted password file' /><br/>
                        </div>

                        <div class='right'>
                            <label class='label'>TMP Path:</label>
                            <input type='text' id='tmp-path' value='<?php print realpath(getcwd()) . DIRECTORY_SEPARATOR . "tmp"; ?>' title='Absolute path to the temporary storage folder' /><br />
                            <?php
                            $log_path = null;
                            if (strtolower(substr(PHP_OS, 0, 3)) == 'lin') {
                                $log_path = "/var/log/sagacity";
                            }
                            else {
                                $log_path = realpath(getcwd()) . DIRECTORY_SEPARATOR . "logs";
                            }

                            ?>
                            <label class='label'>Log Path:</label>
                            <input type='text' id='log-path' value='<?php print $log_path; ?>' title='Absolute path to the log path' /><br />

                            <label class='label'>Log Level:</label>
                            <select id='log-level' title='The default log level'>
                                <option>ERROR</option>
                                <option>WARNING</option>
                                <option>NOTICE</option>
                                <option>DEBUG</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div id='company'>
                    <div class='setup-header'>
                        <h2>Company Information</h2>
                    </div>
                    <div class='buttons'>
                        <input type='button' class='button back' value='Previous' />&nbsp;&nbsp;
                        <input type='button' class='button-delete next' value='Next' disabled="true" />
                    </div>

                    <div class='left'>
                        <label class='label'>Name:</label>
                        <input type='text' id='comp-name' placeholder='Company Name' title='The name of your company' /><br />

                        <label class='label'>Address:</label>
                        <input type='text' id='comp-add' placeholder='Company Address' title='The company address' /><br />

                        <label class='label'>Last Modified By:</label>
                        <input type='text' id='last-modified-by' placeholder='Last modified by?' title='The name of the person that last modified the eChecklist' /><br />

                        <label class='label'>Creator:</label>
                        <input type='text' id='creator' placeholder='Creator' title='Person who created the eChecklist' />
                    </div>

                    <div class='right'>
                        <label class='label'>System Classification:</label>
                        <select id='sys-class'>
                            <option>UNCLASSIFIED</option>
                            <option>U//FOUO</option>
                            <option>SECRET</option>
                        </select>
                        <br />

                        <label class='label'>Classified By:</label>
                        <input type='text' id='classified-by' /><br />

                        <label class='label'>Derived From:</label>
                        <input type='text' id='derived-by' /><br />

                        <label class='label'>SCG Date:</label>
                        <input type='text' id='derived-on' /><br />

                        <label class='label'>Declassify On:</label>
                        <input type='text' id='declassify-on' />
                    </div>
                </div>

                <div id='options'>
                    <div class='setup-header'>
                        <h2>System Options</h2>
                    </div>
                    <div class='buttons'>
                        <input type='button' class='button back' value='Previous' />&nbsp;&nbsp;
                        <input type='button' class='button-delete next' value='Done' disabled="true" />
                    </div>

                    <div class="left">
                        <label for='flatten' class='label'>Flatten eChecklist:</label>
                        <input type='checkbox' id='flatten' checked title='Do you want a high-water mark with the eChecklist exports by default (shows worst case/check)?' /><br />

                        <label for='wrap-text' class='label'>Wrap Text in eChecklist:</label>
                        <input type='checkbox' id='wrap-text' title='Do you want exported eChecklist files to have wrapped text for the check contents field?' /><br />

                        <label for='notifications' class='label'>Scan Notifications:</label>
                        <input type='checkbox' id='notifications' title='Do you want to hear audible notifications when result scans complete' /><br />

                        <label for='port-limit' class='label'>Port Ingestion Limit:</label>
                        <input type="number" id='port-limit' value="100" min="0" max="10000" title="The maximum number of open ports to import from a target (limit 10000)" /><br />

                        <label for='max-results' class='label'>Max # of Result Threads:</label>
                        <input type="number" id='max-results' value="5" min="1" max="20" title="The maximum number of scans to import at a given time (recommended limit of 20)" /><br />

                        <label for='output-format' class='label'>Output format</label>
                        <select id='output-format'>
                            <option value="xlsx">Microsoft Excel 2007+ (.xlsx)</option>
                            <option value="xls">Microsoft Excel 95-2003 (.xls)</option>
                            <option value="ods">OpenDocument Format (.ods)</option>
                            <?php /*
                              <option value="html">HTML (.html)</option>
                              <option value="pdf">Post-script Document (.pdf)</option>
                              <option value="csv">Comma-separated files (.csv)</option>
                             */ ?>
                        </select>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>