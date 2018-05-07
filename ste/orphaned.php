<?php
/**
 * File: orphaned.php
 * Author: Ryan Prather
 * Purpose: Display the findings for a particular host that are not assigned to any checklist
 * Created: Jan 31, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 31, 2014 - File created
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$db = new db();

if (!isset($_REQUEST['tgt'])) {
  print "Need to know what host you want to look at";
  exit;
}

$tgt = $db->get_Target_Details($_REQUEST['ste'], $_REQUEST['tgt'])[0];

$findings = $db->get_Finding($tgt, null, null, true);

set_time_limit(0);
?>

<!DOCTYPE HTML>
<html>
  <head>
    <title><?php print $tgt->get_Name(); ?> - Orphan Findings</title>
    <style type='text/css'>
      #tooltip {
        display: none;
        z-index: 1000;
        background-color: #FFE681;
        color: #000;
        font-size: 16px;
        padding: 4px;
        line-height: 1em;
        position: absolute;
      }
      .hidden {
        display: none;
      }
    </style>

    <script src='../style/5grid/jquery-1.10.2.min.js'></script>
    <script src='../script/default.js'></script>
    <script>
      function pdi_popup(pdi_id, orphan_id) {
        $('#pdi_popup').attr('src', '../data/pdi.php?pdi=' + pdi_id + '&orphan=' + orphan_id);
      }
    </script>
  </head>
  <body onload='javascript:initTip();'>
    <div id='tooltip'></div>
    <table border=1>
      <thead>
        <tr>
          <th>Orphan ID</th>
          <th>VMS ID</th>
          <th>Cat</th>
          <th>IA Controls</th>
          <th>Short Title</th>
          <th>Possible Matches</th>
        </tr>
      </thead>
      <tbody>
        <?php
        foreach ($findings as $key => $finding) {
          $pdi = $db->get_PDI($finding->get_PDI_ID());
          $nessus = null;
          $cve = null;
          $iavm = null;
          $gd = $db->get_GoldDisk_By_PDI($pdi->get_ID());

          $stigs = $db->get_STIG_By_PDI($pdi->get_ID());
          if (!is_a($stigs, 'stig')) {
            die("Can't find the STIG for PDI {$pdi->get_ID()}");
          }

          if (count($gd) == 1) {
            $gd = $gd[0];
          }
          else {
            $gd = null;
          }

          $ia = $db->get_IA_Controls_By_PDI($pdi->get_ID());

          print "<tr>" . PHP_EOL .
              "<td onmouseout='hideTip();' onmouseover='showTip(event, " . $pdi->get_ID() . ");'>" . $stigs->get_ID() . "<div class='hidden' id='" . $pdi->get_ID() . "'>" . nl2br($finding->get_Notes()) . "</div></td>" . PHP_EOL .
              "<td>" . (!is_null($gd) ? $gd->get_ID() : '') . "</td>" . PHP_EOL .
              "<td>" . $pdi->get_Category_Level_String() . "</td>" . PHP_EOL .
              "<td>" . "</td>" . PHP_EOL .
              "<td>" . $pdi->get_Short_Title() . "</td>" . PHP_EOL;

          if (preg_match('/\d{5,6}/', $stigs->get_ID())) {
            $nessus = $db->get_Nessus($stigs->get_ID());
          }
          elseif (preg_match('/CVE\-\d{4}\-\d{4}/', $stigs->get_ID())) {
            $cve = $db->get_CVE($stigs->get_ID());
          }
          elseif (preg_match('/\d{4}\-[ABT]\-\d{4}/', $stigs->get_ID())) {
            $iavm = $db->get_IAVM($stigs->get_ID());
          }
          else {

          }

          $matches = $db->get_Matching_PDIs($pdi, $nessus, $cve, $iavm);

          print "<td>";
          foreach ($matches as $key => $match) {
            $short_desc = nl2br(htmlentities(substr($match['desc'], 0, 500)));
            $short_cont = nl2br(htmlentities(substr($match['check_content'], 0, 1000)));

            print "<div class='hidden' id='" . $match['pdi_id'] . "'>" .
                $short_desc .
                (strlen($match['desc']) > 500 ? " <b>(truncated)</b>" : "") . "<br />" .
                $short_cont .
                (strlen($match['check_content']) > 1000 ? " <b>(truncated)</b>" : "") .
                "</div>";

            print "<a onmouseout='hideTip();'
              onmouseover='showTip(event, " . $match['pdi_id'] . ");'
              href='javascript:void(0);'
              onclick='javascript:pdi_popup(" . $match['pdi_id'] . ",\"" . $stigs->get_ID() . "\");'>" .
                $match['pdi_id'] .
                "</a> (" . $match['score'] . ") " . $match['title'] . "<br />";
          }
          print "</td>";

          print "</tr>" . PHP_EOL;
        }
        ?>
      </tbody>
    </table>
    <iframe id='pdi_popup' class='box' style='width: 80%; height: 80%; top: 10%; left: 10%;'></iframe>
  </body>
</html>
