<?php
/**
 * File: header.inc
 * Author: Ryan Prather
 * Purpose: This file will contain all the standardized header information
 * Created: Sep 11, 2013
 *
 * Portions Copyright 2016-2018: Cyber Perspectives, LLC, All rights reserved
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
 *  - Sep 1, 2016 - Copyright and favicon updated,
 * 					upgraded jQuery to 1.11.3 and jQuery UI to 1.11.4
 *  - Nov 21, 2016 - Added spin.min.js to the header
 *  - Feb 15, 2017 - Formatting
 *  - Dec 27, 2017 - Update get_Settings method to allow for an array
 *  - Jan 2, 2018 - Removed STIG file progress percentage
 *  - Jan 10, 2018 - Added fontawesome CSS library
 *  - Jan 15, 2018 - Added jQuery UI CSS
 *  - Jan 16, 2018 - Added ajax to auto update the cpe, cve, stig, and nasl loading progress.
 *  - Apr 29, 2018 - Updated jQuery and jQuery UI libraries
 *  - May 10, 2018 - Fixed a couple bugs with display
 *  - May 24, 2018 - Fixed order of operation
 *  - Jun 2, 2018 - More bugs
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$db = new db();
global $title_prefix;

$msg = [];

$db->help->select_count("software");
$cpe_count = $db->help->execute();
$cpe       = $db->get_Settings(['cpe-progress', 'cpe-dl-progress']);

if (isset($cpe['cpe-dl-progress']) && between($cpe['cpe-dl-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='cpe-progress'>CPE Download Progress: " . number_format($cpe['cpe-dl-progress'], 0) . "%</div>";
}
elseif (isset($cpe['cpe-progress']) && between($cpe['cpe-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='cpe-progress'>CPE Progress: " . number_format($cpe['cpe-progress'], 0) . "%</div>";
}
elseif (!$cpe_count) {
    $msg[] = "<div id='cpe-progress'>No CPE's present in DB</div>";
}

$db->help->select_count("cve_db");
$cve_count = $db->help->execute();
$cve       = $db->get_Settings([
    'cve-progress', 'cve-dl-progress',
    'nvd-progress', 'nvd-cve-dl-progress', 'nvd-year'
    ]);

if (isset($cve['cve-dl-progress']) && between($cve['cve-dl-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='cve-progress'>CVE Download Progress: " . number_format($cve['cve-dl-progress'], 0) . "%</div>";
}
elseif (isset($cve['nvd-cve-dl-progress']) && between($cve['nvd-cve-dl-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='cve-progress'>NVD CVE Download {$cve['nvd-year']} Progress: " . number_format($cve['nvd-cve-dl-progress'], 0) . "%</div>";
}
elseif (isset($cve['cve-progress']) && between($cve['cve-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='cve-progress'>CVE Progress: " . number_format($cve['cve-progress'], 0) . "%</div>";
}
elseif (isset($cve['nvd-cve-progress']) && between($cve['nvd-cve-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='cve-progress'>NVD CVE {$cve['nvd-year']} Progress: " . number_format($cve['cve-progress'], 0) . "%</div>";
}
elseif (!$cve_count) {
    $msg[] = "<div id='cve-progress'>No CVE's present in DB</div>";
}

$db->help->select_count("stigs");
$stig_count = $db->help->execute();
$stig       = $db->get_Settings(['stig-progress', 'stig-dl-progress']);

if (isset($stig['stig-dl-progress']) && between($stig['stig-dl-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='stig-progress'>STIG Download Progress: " . number_format($stig['stig-dl-progress'], 0) . "%</div>";
}
elseif (isset($stig['stig-progress']) && between($stig['stig-progress'], 0.01, 99.99)) {
    $msg[] = "<div id='stig-progress'>STIG Progress: " .
        "<span id='stig-overall-progress'>" . number_format($stig['stig-progress'], 0) . "%</span>" .
        "</div>";
}
elseif (!$stig_count) {
    $msg[] = "<div id='stig-progress'>No STIG's present in DB</div>";
}

$nasl = $db->get_Settings(['nasl-progress', 'nasl-dl-progress', 'nasl-count']);

if (!$nasl['nasl-count']) {
    if (isset($nasl['nasl-dl-progress']) && between($nasl['nasl-dl-progress'], 0.01, 99.99)) {
        $msg[] = "<div id='nasl-progress'>NASL Download Progress: {$nasl['nasl-dl-progress']}%</div>";
    }
    elseif (isset($nasl['nasl-progress']) && between($nasl['nasl-progress'], 0.01, 99.99)) {
        $msg[] = "<div id='nasl-progress'>NASL Progress: {$nasl['nasl-progress']}%</div>";
    }
}

?>

<!DOCTYPE HTML>
<html>

    <head>

        <title><?php print (isset($title_prefix) ? "$title_prefix | " : ""); ?>Sagacity</title>

        <link href='/style/fonts/fonts.css' rel='stylesheet' type='text/css' />
        <!--[if IE 9]><link rel="stylesheet" href="style/style-ie9.css" /><![endif]-->

        <script src="/script/jquery-3.2.1.min.js"></script>
        <script src="/style/5grid/jquery.browser.min.js"></script>
        <script type="text/javascript" src="/script/jquery-ui/jquery-ui.min.js"></script>
        <script src="/style/5grid/init.js?use=mobile,desktop,1000px&amp;mobileUI=1&amp;mobileUI.theme=none"></script>
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
        <link rel='stylesheet' href='/script/fontawesome/web-fonts-with-css/css/fontawesome-all.min.css' />
        <link rel='stylesheet' href='/script/jquery-ui/jquery-ui.min.css' />

        <meta name="msapplication-TileColor" content="#da532c">
        <meta name="msapplication-TileImage" content="/mstile-144x144.png">

        <script type='text/javascript'>
            $(function () {
              if ($('#db-err')) {
                getLoadStatus();
              }
            });
            function getLoadStatus() {
              $.ajax("/ajax.php", {
                data: {
                  action: 'get-load-status'
                },
                success: function (data) {
                  var reload = false;
                  if ($('#cpe-progress').length) {
                    var cpe = loadValue('cpe-progress', data['cpe-dl-progress'], data['cpe-progress'], data['cpe-count'], 'CPE');
                    if (cpe) {
                      $('#cpe-progress').html(cpe);
                      reload = true;
                    }
                  }

                  if ($('#cve-progress').length) {
                    var cve = loadValue('cve-progress', data['nvd-cve-dl-progress'], data['nvd-cve-progress'], data['nvd-cve-count'], 'NVD CVE', data['nvd-year']);
                    if (cve) {
                      $('#cve-progress').html(cve);
                      reload = true;
                    }
                  }

                  if ($('#stig-progress').length) {
                    var stig = loadValue('stig-progress', data['stig-dl-progress'], data['stig-progress'], data['stig-count'], 'STIG');
                    if (stig) {
                      $('#stig-progress').html(stig);
                      reload = true;
                    }
                  }

                  if ($('#nasl-progress').length) {
                    var nasl = loadValue('nasl-progress', data['nasl-dl-progress'], data['nasl-progress'], data['nasl-count'], 'NASL');
                    if (nasl) {
                      $('#nasl-progress').html(nasl);
                      reload = true;
                    }
                  }

                  if (reload) {
                    setTimeout(getLoadStatus, <?php print UPDATE_FREQ * 1000; ?>);
                  }
                  else {
                    $('#db-err').remove();
                  }
                },
                error: function (xhr, status, error) {
                  console.error(error);
                },
                dataType: 'json',
                method: 'post'
              });
            }

            function loadValue(id, dl, prog, count, msg, nvd_year) {
              if (parseFloat(dl) < 100 && parseFloat(dl) > 0 && parseFloat(prog) === 0) {
                return msg + (typeof nvd_year !== 'undefined' && parseInt(nvd_year) ? ' ' + nvd_year : '') + ' Download Progress ' + parseInt(dl) + "%";
              }
              else if (parseFloat(prog) < 100 && parseFloat(prog) > 0) {
                return msg + (typeof nvd_year !== 'undefined' && parseInt(nvd_year) ? ' ' + nvd_year : '') + ' Progress ' + parseInt(prog) + "%";
              }
              else if (!parseInt(count)) {
                return "No " + msg + "'s present in DB";
              }
              else {
                $('#' + id).remove();
              }
              return false;
            }
        </script>

    </head>

    <body>
        <?php
        if (count($msg)) {
            print "<div id='db-err' style='width:100%;text-align:center;font-size:14pt;background-color:red;color:white;'>" .
                implode("", $msg) .
                "</div>";
        }

        ?>
        <div id="header-wrapper">
            <header id="header" class="5grid-layout">
                <div class="row">
                    <div class="12u">
                        <!-- Nav -->
                        <?php include_once 'menu.inc'; ?>
                        <!-- Logo -->
                        <span class="mobileUI-site-name">
                            <img src='/img/Sagacity-Logo.png' style='width:210px;float:right;' />
                        </span>
                    </div>
                </div>
            </header>
        </div>