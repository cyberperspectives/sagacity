<?php
/**
 * File: echecklist_iframe.php
 * Author: Ryan Prather
 * Purpose: Display the eChecklist in a iFrame popup on the ST&E Mgmt page
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
 *  - Sep 20, 2013 - File created
 *  - Mar 14, 2017 - Formatting and converted direct $_REQUEST to filter_input calls
 *  - Apr 5, 2017 - Formatting
 *  - May 29, 2017 - Fixed bugs
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$db = new db();
set_time_limit(0);
$ste = filter_input(INPUT_GET, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$ste) {
  $ste = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}
$cat = filter_input(INPUT_GET, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$cat) {
  $cat = filter_input(INPUT_POST, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}

$checklists = $db->get_Category_Checklists($cat);
$summary = $db->get_Checklist_Summary($cat);
$cat_tgts = $db->get_Target_By_Category($cat);
$system = $db->get_System_By_STE_ID($ste);
if (!is_a($system, 'system')) {
  die("Could not determine System from ST&amp;E");
}
?>

<!DOCTYPE HTML>

<html>
  <head>
    <script type='text/javascript' src='/style/5grid/jquery-1.11.3.min.js'></script>
    <link rel='stylesheet' type='text/css' href='/style/style.css' />
    <link rel='stylesheet' type='text/css' href='/style/style-desktop.css' />
    <style type="text/css">
      body {
        /*font-family: undefined;*/
        line-height: 1em;
      }

      .header {
        background-color: #ddd9c4;
        font-weight: bold;
        color: #000;
        border: solid 1px #000;
      }

      .not_reviewed,.not_applicable,.not_a_finding,.open,.no_data,.false_positive,.cat_I,.cat_II,.cat_III,.nr,.na,.nf,.nd,.fp {
        text-align: center;
      }

      td {
        font-size: 14px;
        border: solid 1px black;
      }
    </style>
    <script type='text/javascript'>
      $(function () {
        $('.button').mouseover(function () {
          $(this).addClass('mouseover');
        });
        $('.button').mouseout(function () {
          $(this).removeClass('mouseover');
        });
      });
      function check(chk) {
        var val = $(chk).attr('meta:chk') + '-' + $(chk).attr('meta:host');
        $('#' + val).val($(chk).is(':checked') ? '1' : '0');
        $('#export_top,#export_bottom').removeAttr('disabled');
      }
    </script>
  </head>
  <?php flush(); ?>
  <body style='margin: 0; height: 100%;'>
    <a id='top'></a>
    <a class='button' href="javascript:void(0);" id='export_top'
       onclick="$('#export').submit();$('.export').attr('disabled', true);">Export</a>&nbsp;&nbsp;
    <a class='button' href="javascript:void(0);"
       onclick="parent.close_box();">Cancel</a>
    <div style=''>
      <table style='width:100%;border:solid 1px black;border-collapse:collapse;'>
        <tbody>
          <tr>
            <td>&nbsp;</td>
            <?php
            if (is_array($summary['tgts']) && count($summary['tgts'])) {
              foreach ($summary['tgts'] as $name) {
                print "<td>$name</td>";
              }
            }
            ?></tr>
          <?php
          $x = 1;
          foreach ($summary['summary'] as $chk_key => $chklst) {
            print "<tr><td style='width:400px;'><a href='#checklist_{$x}'>{$summary['checklists'][$chk_key]}</a></td>";

            foreach ($summary['summary'][$chk_key] as $host_key => $host) {
              if ($host || $summary['checklists'][$chk_key] == 'Orphan V1R1') {
                print "<td><input type='checkbox' name='chk[$chk_key][$host_key]' meta:chk='$chk_key' meta:host='$host_key' value='1' onclick='javascript:check(this);' checked /></td>";
              }
              else {
                print "<td>&ndash;</td>";
              }
            }

            print "</tr>";
            $x++;
          }
          ?>
        </tbody>
      </table>

      <br /><?php flush(); ?>

      <table style='border-collapse: collapse;'>
        <thead>
          <tr>
            <td class='header' colspan=2 style='width: 153px;'>Open Cat I:</td>
            <td class='open cat_I' style='width: 31px;' id='open_cat_1'><?php print $db->get_Finding_Count_By_Status($cat, "Open", 1); ?></td>
            <td class='header' style='width: 151px;'>System:</td>
            <td
              style='background-color: #ff0; color: #000; font-weight: bold; width: 344px;'><?php print $system->get_Name(); ?></td>
            <td class='header' style='width: 104px;'>Classification:</td>
            <td style='background-color: #ff0; width: 344px; color: #f00; font-weight: bold; width: 287px;'><?php print $system->get_Classification(); ?></td>
            <td rowspan=6 colspan=2 style='width: 375px;'>
              <i style='color:#000;'>Fields marked in yellow are required by the scripts<br />
                to determine formal System Name, hostnames,<br />
                and overall classification. For Classification, use<br />
                UNCLASSIFIED or SECRET.
              </i><br /><br />
              <span style='color: #f00;'>NO SPACES OR SPECIAL CHARS IN HOSTNAMES!</span>
            </td>
          </tr>
          <tr>
            <td class='header' colspan=2>Open Cat II:</td>
            <td class='open cat_II' id='open_cat_2'><?php print $db->get_Finding_Count_By_Status($cat, "Open", 2); ?></td>
            <td class='header'>Hostname(s):</td>
            <td></td>
            <td class='header'>Date(s) Tested:</td>
            <td></td>
          </tr>
          <tr>
            <td class='header' colspan=2>Open Cat III:</td>
            <td class='open cat_III' id='open_cat_3'><?php print $db->get_Finding_Count_By_Status($cat, "Open", 3); ?></td>
            <td class='header'>IP(s):</td>
            <td></td>
            <td class='header'>ST&amp;E Team:</td>
            <td></td>
          </tr>
          <tr>
            <td class='header' colspan=2>Not a Finding:</td>
            <td class='nf' id='not_a_finding'><?php print $db->get_Finding_Count_By_Status($cat, "Not a Finding"); ?></td>
            <td class='header'>Netmask:</td>
            <td></td>
            <td class='header'>OS:</td>
            <td></td>
          </tr>
          <tr>
            <td class='header' colspan=2>N/A:</td>
            <td class='na' id='not_applicable'><?php print $db->get_Finding_Count_By_Status($cat, "Not Applicable"); ?></td>
            <td class='header'>Gateway:</td>
            <td></td>
            <td class='header'>Hardware:</td>
            <td></td>
          </tr>
          <tr>
            <td class='header' colspan=2>Not Reviewed:</td>
            <td class='nr' id='not_reviewed'></td>
            <td class='header'>Description:</td>
            <td></td>
            <td class='header'>Location:</td>
            <td></td>
          </tr>
        </thead>
      </table>

      <br /><?php flush(); ?>

      <?php
      $x = 1;
      $all_nr = 0;

      $findings = $db->get_Category_Findings($cat);

      foreach ($findings as $worksheet_name => $data) {
        print "<a id='checklist_{$x}'></a>";

        if (count($findings) > $x) {
          print "<a href='#checklist_" . ($x + 1) . "'>Next</a>&nbsp;&nbsp;";
        }
        if ($x - 1 != 0) {
          print "<a href='#checklist_" . ($x - 1) . "'>Back</a>&nbsp;&nbsp;";
        }
        print "<a href='#bottom'>Bottom</a>";
        ?>
        <table style="border-collapse:collapse;word-break:break-word;">
          <tbody id='checklist_<?php print $x; ?>'>
            <tr>
              <td class='header' style='width:150px;'>Checklist:</td>
              <td colspan=8 style='color:#000;'><?php
                $chk_arr = array();
                $chk_ids = array();
                $orphan = false;
                foreach ($data['checklists'] as $key => $chk_id) {
                  $chk = $db->get_Checklist($chk_id)[0];
                  $chk_arr[] = "{$chk->get_Name()} V{$chk->get_Version()}R{$chk->get_Release()} ({$chk->get_type()})<br />";
                  $chk_ids[] = $chk->get_ID();
                  if ($chk->get_Name() == 'Orphan') {
                    $orphan = true;
                  }
                }
                sort($chk_arr);
                print implode("", $chk_arr);
                ?></td>
            </tr>
            <tr style='font-weight: bolder;border-bottom:black 3px solid;'>
              <td>&nbsp;</td>
              <td class='cat_I' style='width: 75px;'>I</td>
              <td class='cat_II' style='width: 75px;'>II</td>
              <td class='cat_III' style='width: 75px;'>III</td>
              <td class='na' style='width: 75px;'>NA</td>
              <td class='nf' style='width: 75px;'>NF</td>
              <td class='fp' style='width: 75px;'>FP</td>
              <td class='nd' style='width: 75px;'>ND</td>
              <td class='nr' style='width: 75px;'>NR</td>
            </tr>
            <?php
            $cat_1 = 0;
            $cat_2 = 0;
            $cat_3 = 0;
            $na = 0;
            $nf = 0;
            $fp = 0;
            $nd = 0;
            $nr = 0;
            $total_cat_1 = 0;
            $total_cat_2 = 0;
            $total_cat_3 = 0;
            $total_na = 0;
            $total_nf = 0;
            $total_fp = 0;
            $total_nd = 0;
            $total_nr = 0;
            foreach ($data['target_list'] as $host_name => $col_id) {
              $tgt = $db->get_Target_Details($ste, $host_name)[0];
              $total_cat_1 += $cat_1 = $db->get_Host_Finding_Count_By_Status($tgt, "Open", 1, null, $chk_ids, $orphan);
              $total_cat_2 += $cat_2 = $db->get_Host_Finding_Count_By_Status($tgt, "Open", 2, null, $chk_ids, $orphan);
              $total_cat_3 += $cat_3 = $db->get_Host_Finding_Count_By_Status($tgt, "Open", 3, null, $chk_ids, $orphan);
              $total_na += $na = $db->get_Host_Finding_Count_By_Status($tgt, "Not Applicable", null, null, $chk_ids, $orphan);
              $total_nf += $nf = $db->get_Host_Finding_Count_By_Status($tgt, "Not a Finding", null, null, $chk_ids, $orphan);
              $total_fp += $fp = $db->get_Host_Finding_Count_By_Status($tgt, "False Positive", null, null, $chk_ids, $orphan);
              $total_nd += $nd = $db->get_Host_Finding_Count_By_Status($tgt, "No Data", null, null, $chk_ids, $orphan);
              $total_nr += $nr = $db->get_Host_Finding_Count_By_Status($tgt, "Not Reviewed", null, null, $chk_ids, $orphan);
              $all_nr += $nr;
              ?>
              <tr>
                <td><?php print $tgt->get_Name(); ?></td>
                <td class="cat_I"><?php print $cat_1; ?></td>
                <td class="cat_II"><?php print $cat_2; ?></td>
                <td class="cat_III"><?php print $cat_3; ?></td>
                <td class="na"><?php print $na; ?></td>
                <td class="nf"><?php print $nf; ?></td>
                <td class="fp"><?php print $fp; ?></td>
                <td class="nd"><?php print $nd; ?></td>
                <td class="nr"><?php print $nr; ?></td>
              </tr>
              <?php
            }
            ?>
            <tr style='font-weight:bolder;border-top:black 5px double;'>
              <td style='font-size:16px;'>Total</td>
              <td style='font-size:16px;' class="cat_I"><?php print $total_cat_1; ?></td>
              <td style='font-size:16px;' class="cat_II"><?php print $total_cat_2; ?></td>
              <td style='font-size:16px;' class="cat_III"><?php print $total_cat_3; ?></td>
              <td style='font-size:16px;' class="na"><?php print $total_na; ?></td>
              <td style='font-size:16px;' class="nf"><?php print $total_nf; ?></td>
              <td style='font-size:16px;' class="fp"><?php print $total_fp; ?></td>
              <td style='font-size:16px;' class="nd"><?php print $total_nd; ?></td>
              <td style='font-size:16px;' class="nr"><?php print $total_nr; ?></td>
            </tr>
          </tbody>
        </table>

        <a href='#top'>Top</a><br /> <br />

        <?php
        $x++;
        flush();
      }
      ?>
    </div>

    <script type="text/javascript">
      $(function () {
        $('#not_reviewed').html(<?php print $all_nr; ?>);
      });
    </script>

    <div id='bottom'>
      <form method='post' action='export.php' id='export'>
        <input type='hidden' name='ste' id='ste' value='<?php print $ste; ?>' />
        <input type='hidden' name='cat' id='cat' value='<?php print $cat; ?>' />
        <?php
        foreach ($summary['summary'] as $chk_key => $chk) {
          foreach ($summary['summary'][$chk_key] as $host_key => $host) {
            print "<input type='hidden' name='chk_host[$chk_key][$host_key]' id='{$chk_key}-{$host_key}' value='$host' />";
          }
        }
        ?>
        <a class='button' href="javascript:void(0);" id='export_bottom'
           onclick="$('#export').submit();$('.export').attr('disabled', true);">Export</a>&nbsp;&nbsp;
        <a class='button' href="javascript:void(0);"
           onclick="parent.close_box();">Cancel</a>
      </form>
    </div>
  </body>
</html>