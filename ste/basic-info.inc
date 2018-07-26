<?php
/**
 * File: basic-info.inc
 * Author: Ryan Prather
 * Purpose: Display the basic information from the target
 * Created: Sep 1, 2016
 *
 * Copyright 2016-2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 1, 2016 - File created
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 *  - Apr 19, 2018 - Updated 3rd party libraries
 */
?>

<style type='text/css'>
  #basic-info {
    border: solid 1px black;
    height: 170px;
    text-align: left;
  }

  #osSoftware {
    float: right;
    text-align: right;
    height: 62px;
  }

  #availableOS {
    position: absolute;
    text-align: left;
    background-color: white;
    border: solid 1px black;
    z-index: 100;
    overflow-x: scroll;
    height: 250px;
    width: 400px;
  }

  .swmouseover {
    background-color:#1D57A0;
    color:#fff;
    cursor:pointer;
  }

  .ui-timepicker-div .ui-widget-header { margin-bottom: 8px; }
  .ui-timepicker-div dl { text-align: left; }
  .ui-timepicker-div dl dt { float: left; clear:left; padding: 0 0 0 5px; }
  .ui-timepicker-div dl dd { margin: 0 10px 10px 40%; }
  .ui-timepicker-div td { font-size: 90%; }
  .ui-tpicker-grid-label { background: none; border: none; margin: 0; padding: 0; }
  .ui-timepicker-div .ui_tpicker_unit_hide{ display: none; }

  .ui-timepicker-rtl{ direction: rtl; }
  .ui-timepicker-rtl dl { text-align: right; padding: 0 5px 0 0; }
  .ui-timepicker-rtl dl dt{ float: right; clear: right; }
  .ui-timepicker-rtl dl dd { margin: 0 40% 10px 10px; }

  /* Shortened version style */
  .ui-timepicker-div.ui-timepicker-oneLine { padding-right: 2px; }
  .ui-timepicker-div.ui-timepicker-oneLine .ui_tpicker_time,
  .ui-timepicker-div.ui-timepicker-oneLine dt { display: none; }
  .ui-timepicker-div.ui-timepicker-oneLine .ui_tpicker_time_label { display: block; padding-top: 2px; }
  .ui-timepicker-div.ui-timepicker-oneLine dl { text-align: right; }
  .ui-timepicker-div.ui-timepicker-oneLine dl dd,
  .ui-timepicker-div.ui-timepicker-oneLine dl dd > div { display:inline-block; margin:0; }
  .ui-timepicker-div.ui-timepicker-oneLine dl dd.ui_tpicker_minute:before,
  .ui-timepicker-div.ui-timepicker-oneLine dl dd.ui_tpicker_second:before { content:':'; display:inline-block; }
  .ui-timepicker-div.ui-timepicker-oneLine dl dd.ui_tpicker_millisec:before,
  .ui-timepicker-div.ui-timepicker-oneLine dl dd.ui_tpicker_microsec:before { content:'.'; display:inline-block; }
  .ui-timepicker-div.ui-timepicker-oneLine .ui_tpicker_unit_hide,
  .ui-timepicker-div.ui-timepicker-oneLine .ui_tpicker_unit_hide:before{ display: none; }
</style>
<link href="/script/jquery-ui/jquery-ui.min.css" rel="stylesheet" type="text/css" />

<script src='/script/jQueryUI/jquery-ui-timepicker-addon.js' type='text/javascript'></script>
<script type='text/javascript'>
  $(function () {
    $('#last_boot').datetimepicker({dateFormat: "YY-mm-dd", timeFormat: "HH:mm:ss", pickerTimeFormat: "HH:mm:ss", showSecond: true});
  });

  /**
   *
   */
  function filter_os() {
    if ($('#os_filter').val().length < 3) {
      $('#availableOS').html('');
      $('#availableOS').hide();
      return;
    }
    $.ajax('/ajax.php', {
      data: {
        action: 'os_filter',
        tgt_id: '<?php print isset($_REQUEST['tgt']) ? $_REQUEST['tgt'] : ''  ?>',
        filter: $('#os_filter').val()
      },
      success: update_os_filter,
      dataType: 'html',
      method: 'post'
    });
  }

  /**
   *
   */
  function update_os_filter(data) {
    $('#availableOS').html(data);
    $('#availableOS').show();
    $('#availableOS div').each(function () {
      $(this).on("mouseover", function () {
        $(this).addClass("swmouseover");
      });
      $(this).on("mouseout", function () {
        $(this).removeClass("swmouseover");
      });
      $(this).on("click", function () {
        $('#availableOS').hide();
        $('#osSoftware').html($(this).text() + "<input type='hidden' name='osSoftware' value='" + $(this).attr('sw_id') + "' />");
      });
    });
  }
</script>

<div class='title'>Basic Information (<?php print $sys->get_Name() . ", " . $site->get_Name() . ", " . $ste->get_Eval_Start_Date()->format("d M, Y"); ?>)</div>

<div id='basic-info'>
  <div class='data-row' style='width:190px;'>
    <input type='text' name='name' class='auto-update-text' placeholder='Name...' value='<?php
    if (!empty($tgt)) {
      print $tgt->get_Name();
    }
    ?>' /><br />

    <input type='text' id='os_filter' title='CPE string' placeholder='Filter OS...' onkeyup="javascript:filter_os();" autocomplete="off" /><br />
    <div id="availableOS" onmouseover="$(this).show();" onmouseout="$(this).hide();" style="display:none;"></div>

    <input type='text' name='location' class='auto-update-text' placeholder='Location...' value="<?php
    if (!empty($tgt)) {
      print $tgt->get_Location();
    }
    ?>" /><br />

    <select name='classification' style='width:173px;' class='auto-update-select'>
      <option>-- Classification --</option>
      <option value="U"<?php
      if (!empty($tgt) && $tgt->classification == 'U') {
        print " selected";
      }
      ?>>Public/UNCLASSIFED</option>
      <option value="FOUO"<?php
      if (!empty($tgt) && $tgt->classification == 'FOUO') {
        print " selected";
      }
      ?>>Sensitive/FOUO</option>
      <option value="S"<?php
      if (!empty($tgt) && $tgt->classification == 'S') {
        print " selected";
      }
      ?>>Classified/SECRET</option>
    </select><br />

    <input type='text' id='last_boot' name='last_boot' class='auto-update-text' placeholder='Last Boot' value="<?php
    if (!empty($tgt) && is_a($tgt->get_Last_Boot(), "DateTime")) {
      print $tgt->get_Last_Boot()->format("Y-m-d H:i:s");
    }
    else {
      print "1970-01-01 00:00:00";
    }
    ?>" />
  </div>

  <div class='data-row' style='width:190px;'>
    <label for='vm'>Virtual Machine?</label>
    <input type='checkbox' name='vm' id='vm' class='auto-update-check' value='1' <?php
    if (!empty($tgt) && $tgt->is_VM()) {
      print "checked";
    }
    ?> /><br />

    <span id="osSoftware">
      <?php
      if (isset($_REQUEST['tgt'])) {
        $os = $db->get_Software($tgt->get_OS_ID())[0];
        print $os->get_SW_String();
        print "<input type='hidden' name='osSoftware' value='" . $os->get_ID() . "' />";
      }
      ?>
    </span><br />

    <input type='text' name='wmi_pid' class='auto-update-text' placeholder="WMI PID" value="<?php
    if (!empty($tgt)) {
      print $tgt->get_WMI_PID();
    }
    ?>" /><br />

    <input type='text' name='last_login' class='auto-update-text' placeholder='Last Login...' value="<?php
    if (!empty($tgt)) {
      print $tgt->get_Last_Login();
    }
    ?>" />
  </div>

  <div class='data-row' style='width:190px;'>
    Auto: <select name='auto_status' class='auto-update-select'>
      <?php
      if (!empty($tgt)) {
        $status_id = !is_null($tgt->get_Auto_Status_ID()) ? $tgt->get_Auto_Status_ID() : 5;
      }
      else {
        $status_id = 5;
      }

      foreach ($task_status as $key => $val) {
        print "<option value='$key'" . ($key == $status_id ? " selected " : "") . ">$val</option>";
      }
      ?>
    </select><br />

    Manual: <select name='man_status' class='auto-update-select'>
      <?php
      if (!empty($tgt)) {
        $status_id = !is_null($tgt->get_Man_Status_ID()) ? $tgt->get_Man_Status_ID() : 5;
      }
      else {
        $status_id = 5;
      }

      foreach ($task_status as $key => $val) {
        print "<option value='$key'" . ($key == $status_id ? " selected " : "") . ">$val</option>";
      }
      ?>
    </select><br />

    Data: <select name='data_status' class='auto-update-select'>
      <?php
      if (!empty($tgt)) {
        $status_id = !is_null($tgt->get_Data_Status_ID()) ? $tgt->get_Data_Status_ID() : 5;
      }
      else {
        $status_id = 5;
      }

      foreach ($task_status as $key => $val) {
        print "<option value='$key'" . ($key == $status_id ? " selected " : "") . ">$val</option>";
      }
      ?>
    </select><br />

    FP/Cat I: <select name='fp-cat1_status' class='auto-update-select'>
      <?php
      if (!empty($tgt)) {
        $status_id = !is_null($tgt->get_FP_Cat1_Status_ID()) ? $tgt->get_FP_Cat1_Status_ID() : 5;
      }
      else {
        $status_id = 5;
      }

      foreach ($task_status as $key => $val) {
        print "<option value='$key'" . ($key == $status_id ? " selected " : "") . ">$val</option>";
      }
      ?>
    </select><br />

    <input type='text' name='login' class='auto-update-text' placeholder='Login...' value='<?php
    if (!empty($tgt)) {
      print $tgt->get_Login();
    }
    ?>' />
  </div>

  <div class='data-row' style='width:579px;'>
    <textarea name='notes' class='auto-update-text' cols=79 rows=10><?php
      if (!empty($tgt)) {
        print $tgt->get_Notes();
      }
      ?></textarea>
  </div>

</div>
