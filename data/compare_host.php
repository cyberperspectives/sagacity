<?php
/**
 * File: compare_host.php
 * Author: Ryan Prather
 * Purpose: Allow the comparaison between 2 targets
 * Created: Dec 16, 2014
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
 *  - Dec 16, 2014 - File created
 *  - Sep 1, 2016 - Updated copyright and file purpose
 */

include_once 'database.inc';
include_once 'header.inc';

$db = new db();

$left_tgt = $db->get_Target_Details($_REQUEST['left_ste'], $_REQUEST['left_tgt'])[0];
$right_tgt = $db->get_Target_Details($_REQUEST['right_ste'], $_REQUEST['right_tgt'])[0];

$findings = $db->get_Finding_Comparrison($left_tgt, $right_tgt);
?>

<style type='text/css'>
.none {
  background-color: #808080;
}
.header {
  color: #000;
}
td, th {
  border: solid 1px black;
}
</style>

<div id="wrapper">
  <div id="main-wrapper">
    <div class="12u" id="main-content">
      <div class="5grid-layout" style="text-align: right;">
        <div class="row">
          <div class="12u">
            <table style="width:100%;">
              <thead>
                <tr>
                  <th class='header'>STIG ID</th>
                  <th class='header'>CAT</th>
                  <th class='header'>IA Controls</th>
                  <th class='header'>Left Status</th>
                  <th class='header'>Right Status</th>
                  <th class='header'>Left Notes</th>
                  <th class='header'>Right Notes</th>
                </tr>
              </thead>

              <tbody>
<?php
$odd = true;
foreach($findings['left'] as $stig_id => $find) {
?>
                <tr class="<?php print ($odd ? "odd" : "even"); ?>_row">
                  <td><?php print $stig_id; ?></td>
<?php
  $str = "";
  $diff = false;
  if(is_null($find)) {
    $str .= "&nbsp;";
  }
  else {
    $str .= str_repeat("I", $find['cat']);
  }

  if(isset($findings['right'][$stig_id])) {
    $str .= " / ".str_repeat("I", $findings['right'][$stig_id]['cat']);
    if($find['cat'] != $findings['right'][$stig_id]['cat']) {
      $diff = true;
    }
  }
  else {
    $str .= " /";
  }

  if($diff) {
    print "<td style='background-color:#FFF200;'>".$str."</td>";
  }
  else {
    print "<td>".$str."</td>";
  }

  $str = "";
  $diff = false;
  if(is_null($find)) {
    $str .= "&nbsp;";
  }
  else {
    $str .= $find['ia_controls'];
  }

  if(isset($findings['right'][$stig_id])) {
    $str .= " / ".$findings['right'][$stig_id]['ia_controls'];
    if($find['ia_controls'] != $findings['right'][$stig_id]['ia_controls']) {
      $diff = true;
    }
  }
  else {
    $str .= " /";
  }

  if($diff) {
    print "<td style='background-color:#FFF200;'>".$str."</td>";
  }
  else {
    print "<td>".$str."</td>";
  }

  $str = "";
  if(is_null($find)) {
    $str .= "<td class='nr'>Not Reviewed</td>";
  }
  else {
    $status = strtolower(str_replace(" ", "_", $find['status']));
    $str .= "<td class='$status'>".$find['status']."</td>";
  }

  if(isset($findings['right'][$stig_id])) {
    $status = strtolower(str_replace(" ", "_", $findings['right'][$stig_id]['status']));
    $str .= "<td class='$status'>".$findings['right'][$stig_id]['status']."</td>";
  }
  else {
    $str .= "<td class='nr'>Not Reviewed</td>";
  }

  print $str;

  $str = "";
  if(is_null($find)) {
    $str .= "<td>&nbsp;</td>";
  }
  else {
    $str .= "<td>".$find['notes']."</td>";
  }

  if(isset($findings['right'][$stig_id])) {
    $str .= "<td>".$findings['right'][$stig_id]['notes']."</td>";
  }
  else {
    $str .= "<td>&nbsp;</td>";
  }

  print $str;

  $odd = !$odd;
}
?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
