<?php
/**
 * File: target.php
 * Author: Teresa Campos
 * Purpose: Display target data
 * Created: Sep 17, 2013
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
 *  - Sep 17, 2013 - File created
 *  - Oct 24, 2013 - Last modified
 *  - Jan 15, 2014 - Added ability to turn off post processing
 *  - Sep 1, 2016 - Copyright Updated
 *  - Oct 24, 2016 - Mostly fixed formatting, but also some style updates
 *  - Dec 7, 2016 - Changed DOC_ROOT."/tmp..." to TMP constant
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 *  - Apr 5, 2017 - Formatting...still have a lot to do to this!
 *  - May 19, 2017 - Changed buttons to match and fixed error with OS filtering, and error when creating target in a category
 *  - Aug 28, 2017 - Fixed bug when removing checklists or software
 *  - Oct 26, 2017 - Added check_path for /tmp/data_collection directory to make sure the parent directory is there before it attempts to create any target subdirectories
 *  - Oct 27, 2017 - Fix bug for deleting interfaces
 *  - Jan 10, 2018 - Update STE object to use System and Site class member variables instead of ID's
 */
set_time_limit(0);
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

check_path(TMP . "/data_collection");

$db = new db();
$findings_deleted = false;

$delete_tgt = filter_input(INPUT_GET, 'delete_tgt', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$delete_findings = filter_input(INPUT_GET, 'delete_tgt_findings', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$tgt_id = filter_input(INPUT_GET, 'tgt', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$sec_tgt = filter_input(INPUT_POST, 'sec_tgt', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$cat_id = filter_input(INPUT_POST, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$cat_id) {
  $cat_id = filter_input(INPUT_GET, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}
$ste_id = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$ste_id) {
  $ste_id = filter_input(INPUT_GET, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}

if (!$ste_id) {
  $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}

if ($delete_tgt) {
  $db->delete_Target($delete_tgt);
  header("Location: index.php");
}
elseif ($delete_findings) {
  $db->delete_Target_Findings($delete_tgt_findings);
  $findings_deleted = true;
}
elseif ($sec_tgt > 0) {
  $tgt_id = filter_input(INPUT_POST, 'tgt', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
  $db->merge_Target($ste_id, $tgt_id, $sec_tgt);
}

$required = "<span class='ErrorMsg' title='Required' style='float:none;'>*&nbsp;</span>";

$task_status = $db->get_Task_Statuses();

$gen_os = $db->get_Software("cpe:/o:generic:generic:-");
if (is_array($gen_os) && count($gen_os) && isset($gen_os[0]) && is_a($gen_os[0], 'software')) {
  $gen_os = $gen_os[0];
}

// Update or insert new target
if ($action == 'insert') {
  $params = array(
    'cat'                      => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1)),
    'ste'                      => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1)),
    "Classification"           => array('filter' => FILTER_VALIDATE_REGEXP, 'options' => array('regexp' => "/U|FOUO|S/")),
    "DeviceName"               => FILTER_SANITIZE_STRING,
    "osSoftware"               => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1)),
    "location"                 => FILTER_SANITIZE_STRING,
    "automated_taskStatus"     => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "manual_taskStatus"        => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "dataGathering_taskStatus" => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "fp_CAT1_taskStatus"       => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "applicableChecklists"     => array('filter' => FILTER_VALIDATE_INT, 'flags' => FILTER_REQUIRE_ARRAY),
    "suspend_pp"               => array('filter' => FILTER_VALIDATE_BOOLEAN, 'flags' => FILTER_NULL_ON_FAILURE),
    "targetNotes"              => FILTER_SANITIZE_STRING
  );

  $vals = filter_input_array(INPUT_POST, $params);

  $tgt = new target($vals['DeviceName']);
  $tgt->set_STE_ID($vals['ste']);
  $tgt->set_Auto_Status_ID($vals['automated_taskStatus']);
  $tgt->set_Man_Status_ID($vals['manual_taskStatus']);
  $tgt->set_Data_Status_ID($vals['dataGathering_taskStatus']);
  $tgt->set_FP_Cat1_Status_ID($vals['fp_CAT1_taskStatus']);
  $tgt->set_Location($vals['location']);
  $tgt->classification = $vals['Classification'];
  $tgt->set_Notes(trim($vals['targetNotes']));
  $tgt->set_PP_Suspended((boolean) $vals['suspend_pp']);

  if ($vals['cat'] && is_numeric($vals['cat'])) {
    $tgt->set_Cat_ID($vals['cat']);
  }

  if (is_array($vals['applicableChecklists']) && count($vals['applicableChecklists'])) {
    foreach ($vals['applicableChecklists'] as $chk_id) {
      $chk = $db->get_Checklist($chk_id);
      if (is_array($chk) && count($chk) && isset($chk[0]) && is_a($chk[0], 'checklist')) {
        $tgt->checklists[$chk_id] = $chk[0];
      }
    }
  }
  else {
    foreach ($tgt->checklists as $key => $chk) {
      unset($tgt->checklists[$key]);
    }
  }

  if ($vals['osSoftware'] > 0) {
    $os = $db->get_Software($vals['osSoftware']);
    if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
      $tgt->set_OS_ID($os[0]->get_ID());
      $tgt->set_OS_String($os[0]->get_Shortened_SW_String());
    }
  }

  $ret = $db->save_Target($tgt);

  if (!$ret) {
    print 'Error Saving Target';
  }

  header('Location: /ste/index.php');
}
elseif ($action == 'update') {
  $params = array(
    "Classification"           => array('filter' => FILTER_VALIDATE_REGEXP, 'options' => array('regexp' => "/U|FOUO|S/")),
    "DeviceName"               => FILTER_SANITIZE_STRING,
    'ste'                      => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1)),
    "tgt"                      => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1)),
    "osSoftware"               => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1)),
    "location"                 => FILTER_SANITIZE_STRING,
    "automated_taskStatus"     => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "manual_taskStatus"        => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "dataGathering_taskStatus" => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "fp_CAT1_taskStatus"       => array('filter' => FILTER_VALIDATE_INT, 'options' => array('min_range' => 1, 'max_range' => 5)),
    "applicableChecklists"     => array('filter' => FILTER_VALIDATE_INT, 'flags' => FILTER_REQUIRE_ARRAY),
    "installedSoftware"        => array('filter' => FILTER_VALIDATE_INT, 'flags' => FILTER_REQUIRE_ARRAY),
    "suspend_pp"               => array('filter' => FILTER_VALIDATE_BOOLEAN, 'flags' => FILTER_NULL_ON_FAILURE),
    "targetNotes"              => FILTER_SANITIZE_STRING,
    "missingPatches"           => FILTER_SANITIZE_STRING,
    "netstatConnections"       => FILTER_SANITIZE_STRING,
    "login"                    => FILTER_SANITIZE_STRING,
    "new"                      => array('filter' => FILTER_VALIDATE_INT, 'flags' => FILTER_REQUIRE_ARRAY),
    "ip"                       => array('filter' => FILTER_SANITIZE_STRING, 'flags' => FILTER_REQUIRE_ARRAY),
    "hostname"                 => array('filter' => FILTER_SANITIZE_STRING, 'flags' => FILTER_REQUIRE_ARRAY),
    "name"                     => array('filter' => FILTER_SANITIZE_STRING, 'flags' => FILTER_REQUIRE_ARRAY),
    "fqdn"                     => array('filter' => FILTER_SANITIZE_STRING, 'flags' => FILTER_REQUIRE_ARRAY),
    "description"              => array('filter' => FILTER_SANITIZE_STRING, 'flags' => FILTER_REQUIRE_ARRAY)
  );

  $vals = filter_input_array(INPUT_POST, $params);

  $tgt = $db->get_Target_Details($vals['ste'], $vals['tgt']);
  if (is_array($tgt) && count($tgt) && isset($tgt[0]) && is_a($tgt[0], 'target')) {
    $tgt = $tgt[0];
  }
  else {
    die(nl2br(print_r($tgt, true)));
  }

  $tgt->set_ID($vals['tgt']);
  $tgt->set_Name($vals['DeviceName']);
  $tgt->set_STE_ID($vals['ste']);
  $tgt->set_Auto_Status_ID($vals['automated_taskStatus']);
  $tgt->set_Man_Status_ID($vals['manual_taskStatus']);
  $tgt->set_Data_Status_ID($vals['dataGathering_taskStatus']);
  $tgt->set_FP_Cat1_Status_ID($vals['fp_CAT1_taskStatus']);
  $tgt->set_Location($vals['location']);
  $tgt->classification = $vals['Classification'];
  $tgt->set_Notes(trim($vals['targetNotes']));
  $tgt->set_Netstat_Connections(trim($vals['netstatConnections']));
  $tgt->set_Missing_Patches(trim($vals['missingPatches']));
  $tgt->set_Login($vals['login']);
  $tgt->set_PP_Suspended((boolean) $vals['suspend_pp']);

  if ($vals['osSoftware'] > 0) {
    $os = $db->get_Software($vals['osSoftware']);
    if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
      $tgt->set_OS_ID($os[0]->get_ID());
      $tgt->set_OS_String($os[0]->get_Shortened_SW_String());
    }
  }

  if (is_array($vals['applicableChecklists']) && count($vals['applicableChecklists'])) {
    $tgt->checklists = array();
    foreach ($vals['applicableChecklists'] as $chk_id) {
      $chk = $db->get_Checklist($chk_id);
      if (is_array($chk) && count($chk) && isset($chk[0]) && is_a($chk[0], 'checklist')) {
        $tgt->checklists[$chk_id] = $chk[0];
      }
    }
  }
  else {
    foreach ($tgt->checklists as $key => $chk) {
      unset($tgt->checklists[$key]);
    }
  }

  if (is_array($vals['installedSoftware']) && count($vals['installedSoftware'])) {
    $tgt->software = array();
    foreach ($vals['installedSoftware'] as $sw_id) {
      $sw = $db->get_Software($sw_id);
      if (is_array($sw) && count($sw) && isset($sw[0]) && is_a($sw[0], 'software')) {
        $tgt->software[$sw_id] = $sw[0];
      }
    }
  }
  else {
    foreach ($tgt->software as $key => $chk) {
      unset($tgt->software[$key]);
    }
  }

  if (is_array($vals['ip']) && count($vals['ip'])) {
    foreach ($vals['ip'] as $id => $ip) {
      $ipv4 = null;
      $ipv6 = null;
      if (preg_match("/:/", $ip)) {
        $ipv6 = $ip;
      }
      else {
        $ipv4 = $ip;
      }

      if (strtolower($ip) == 'delete') {
        foreach ($tgt->interfaces as $idx => $int) {
          if ($int->get_ID() == $id) {
            Sagacity_Error::err_handler("Deleting target ({$tgt->get_ID()}) interface (ID: {$int->get_ID()} IP: $ip)");
            unset($tgt->interfaces["{$idx}"]);
            break;
          }
        }
        $db->delete_Interface($id);
      }
      else {
        if (isset($tgt->interfaces["$ip"])) {
          $int = $tgt->interfaces["$ip"];
          $int->set_Name($vals['name'][$id]);
          $int->set_IPv4($ipv4);
          $int->set_IPv6($ipv6);
          $int->set_Description($vals['description'][$id]);
          $int->set_Hostname($vals['hostname'][$id]);
          $int->set_FQDN($vals['fqdn'][$id]);
        }
        else {
          $int = new interfaces(null, $tgt->get_ID(), $vals['name'][$id], $ipv4, $ipv6, $vals['hostname'][$id], $vals['fqdn'][$id], $vals['description'][$id]);
        }

        $tgt->interfaces["$ip"] = $int;
      }
    }
  }

  $ret = $db->save_Target($tgt);

  header("Location: /ste/");
}
elseif ($action == 'data_collection') {
  include_once 'import.inc';
  $import = new import();
  $import->import_Host_Data_Collection();
}

// If there is 'tgt' in the querystring
if ($tgt_id && $ste_id) {
  $tgt = $db->get_Target_Details($ste_id, $tgt_id)[0];

  $ste = $db->get_STE($tgt->get_STE_ID())[0];
}
else {
  $tgt = null;
  $checklists = array();
}

$title_prefix = ($tgt_id ? "Edit " . $tgt->get_Name() : "Add Target");
include_once 'header.inc';
?>
<style type="text/css">

  /* Tables */
  input.Control, select.Control, textarea.Control {
    float: left;
    resize: none;
  }

  td.Control {
    vertical-align: bottom;
    padding: 0px 20px 5px 10px;
  }

  td.Label {
    padding-left: 15px;
  }

  tr.DynamicContent td {
    text-align: center;
  }

  table.Border {
    border: 2px solid black;
  }

  .Text {
    padding-left: 30px;
    font-size: 18px;
    font-weight: bold;
    text-align: left;
    background-color: #31363C;
  }

  .Head {
    background-color: #31363C;
    color: #fff;
    margin-top: 20px;
    padding: 15px 30px;
  }

  .header {
    text-align: center;
    width: 1px;
    background-color: #31363C;
    display: table-cell;
    color: #fff;
  }

  .label {
    display: inherit;
    padding-top: 10px;
  }

  .Space {
    padding-left: 3px;
  }

  .ErrorMsg {
    float: left;
    color: red;
    padding-left: 5px;
  }

  .highlight {
    border: 2px solid red;
  }

  #availableSoftware {
    height: 227px;
    width: 240px;
    overflow-x: scroll;
    font-size: 14px;
    line-height: 1.25em;
  }

  #osSoftware {
    float: right;
    width: 300px;
    text-align: right;
    padding-right: 5px;
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
    background-color: #1D57A0;
    color: #fff;
    cursor: pointer;
  }

  .pps-row span {
    display: table-cell;
  }

  .pps {
    width: 100px;
    text-align: center;
  }

  .iana-name {
    width: 160px;
  }

  .listen {
    width: 125px;
    text-align: center;
  }

  .banner {
    width: 310px;
  }

  .pps-notes {
    width: 505px;
  }
</style>
<script src='ste_script.js' type='text/javascript'></script>
<script type="text/javascript" src="/script/dropzone/dropzone.min.js"></script>
<link type="text/css" href="/script/dropzone/dropzone.min.css" rel="stylesheet" />
<link type="text/css" href="/script/dropzone/basic.min.css" rel="stylesheet" />

<script type="text/javascript">
  var mydz;
  Dropzone.options.dropzone = {
    maxFilesize: 150,
    success: function (file, res) {
      res = JSON.parse(res);
      if (res.imageUrl) {
        this.emit('thumbnail', file, res.imageUrl);
      }
    },
    dictCancelUpload: "Cancel Upload",
    dictCancelUploadConfirmation: "Are you sure you want to cancel this upload?"
  };
  Dropzone.prototype.submitRequest = function (xhr, formData, files) {
    var dt = new Date(files[0].lastModifiedDate);
    xhr.setRequestHeader('X-FILENAME', files[0].name);
    xhr.setRequestHeader('X-FILEMTIME', dt.toISOString());
    return xhr.send(formData);
  };
  Dropzone.autoDiscover = false;
  $(function () {
    $('#add_interface').click(add_interface);
    $('.button').mouseover(function () {
      $(this).addClass('mouseover');
    });
    $('.button').mouseout(function () {
      $(this).removeClass('mouseover');
    });
<?php if ($tgt_id) { ?>
      mydz = new Dropzone('#dropzone');
<?php } ?>
  });
  /**
   * Function to validate that the user really wants to delete the target
   */
  function validateDelete() {
    if (confirm("Are you sure you want to delete this host?")) {
      location.href = "target.php?delete_tgt=<?php print $tgt_id ? $tgt_id : 0; ?>";
    }
  }

  /**
   * Function to validate that the user really wants to delete the target findings
   */
  function validateDeleteFindings() {
    if (confirm("Are you sure you want to delete ALL findings for this host?")) {
      location.href = "target.php?delete_tgt_findings=<?php print $tgt_id ? $tgt_id : 0; ?>";
    }
  }

  /**
   * Function to filter the checklists
   *
   * @param {boolean} bln_hide_old
   *    Parameter to decide if you want to hide old checklists in the filtering and only show the most current checklist
   */
  function filter_checklists(bln_hide_old) {
    $.ajax('/ajax.php', {
      data: {
        action: 'chk_filter',
        filter: $('#chk_filter').val(),
        tgt_id: '<?php print $tgt_id ? $tgt_id : ''; ?>',
        hide_old: bln_hide_old
      },
      success: function (data) {
        data = JSON.parse(data);
        $('#availableChecklists option').remove();
        for (var x in data) {
          var type = '';
          if (data[x].type == 'iavm') {
            type = data[x].type.toString().toUpperCase();
          }
          else {
            type = data[x].type.toString().charAt(0).toUpperCase() + data[x].type.toString().slice(1);
          }
          $('#availableChecklists').append("<option id='" + data[x].id + "' value='" + data[x].id + "' title='" +
                  data[x].name + " V" + data[x].ver + "R" + data[x].release + " (" + data[x].type + ")'>" +
                  data[x].name + " V" + data[x].ver + "R" + data[x].release + " (" + type + ")</option>");
        }
      },
      error: function (xhr, status, error) {
        console.error(error);
      },
      datatype: 'json',
      method: 'post'
    });
  }

  /**
   * Function to search and find software matching the filter criteria
   *
   * @todo merge this and filter_os calls
   */
  function filter_software() {
    $.ajax('/ajax.php', {
      data: {
        action: 'sw_filter',
        tgt_id: '<?php print $tgt_id ? $tgt_id : ''; ?>',
        filter: $('#sw_filter').val()
      },
      success: function (data) {
        $('#availableSoftware div').remove();
        for (var x in data) {
          $('#availableSoftware').append("<div sw_id='" + data[x].sw_id + "' cpe='" + data[x].cpe + "'>" + data[x].sw_string + "</div>");
        }

        $('#availableSoftware div').each(function () {
          $(this).on("mouseover", function () {
            $(this).addClass("swmouseover");
          });
          $(this).on("mouseout", function () {
            $(this).removeClass("swmouseover");
          });
          $(this).on("click", function () {
            $('#installedSoftware').append("<option value='" + $(this).attr('sw_id') + "' ondblclick='$(this).remove();'>" + $(this).html() + "</option>");
            $(this).remove();
          });
        });
      },
      dataType: 'json',
      method: 'post',
      timeout: 5000
    });
  }


  /**
   * Function to filter the operating systems
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
        tgt_id: '<?php print $tgt_id ? $tgt_id : ''; ?>',
        filter: $('#os_filter').val()
      },
      success: function (data) {
        $('#availableOS div').remove();
        for (var x in data) {
          $('#availableOS').append("<div sw_id='" + data[x].sw_id + "' cpe='" + data[x].cpe + "'>" + data[x].sw_string + "</div>");
        }

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
            $('#osSoftware').html($(this).text() + "<input type='hidden' name='osSoftware' id='os_id' value='" + $(this).attr('sw_id') + "' />");
          });
        });
      },
      dataType: 'json',
      method: 'post',
      timeout: 5000
    });
  }

  /**
   * Function to add a new interface
   */
  function add_interface() {
    $('#Interface').append("<tr class='DynamicContent " + ($odd ? "odd_row" : "even_row") + "'>" +
            "<td><input type='hidden' name='new[" + $int_id + "]' value='1' /><input type='text' style='width:100px;' name='ip[" + $int_id + "]' /></td>" +
            "<td><input type='text' style='width:215px;' name='hostname[" + $int_id + "]' /></td>" +
            "<td><input type='text' style='width:215px;' name='name[" + $int_id + "]' /></td>" +
            "<td><input type='text' style='width:215px;' name='fqdn[" + $int_id + "]' /></td>" +
            "<td><textarea style='width:390px;vertical-align:bottom;' rows='2' name='description[" + $int_id + "]'></textarea></td>" +
            "</tr>"
            );
    $odd = !$odd;
    $int_id++;
  }

  function open_upload() {
    $('#upload_div').animate({
      'opacity': '1.00'
    }, 300, 'linear');
    $('#upload_div').css('display', 'block');
    view_box();
  }
</script>
<div id="wrapper" style='overflow-x:hidden;overflow-y:scroll;'>
  <div id="main-wrapper">
    <form method='post' id='target' action='target.php'>
      <?php print ($cat_id ? "<input type='hidden' name='cat' value='{$cat_id}' />" : ''); ?>
      <input type="hidden" name="action" id="action" value="<?php print $tgt_id ? "update" : "insert"; ?>" />
      <input type="hidden" name="tgt" value="<?php print $tgt_id ? $tgt_id : ''; ?>" />
      <input type='hidden' id='gen-os' value='<?php print (isset($gen_os) && is_a($gen_os, 'software') ? $gen_os->get_ID() : '1'); ?>' />
      <div class="12u" id="main-content">
        <!-- -->
        <div class="modal"></div>
        <div class="5grid-layout" style="text-align: right;">
          <div class="row">
            <div class="12u">
              <div>
                <?php
                if ($findings_deleted) {
                  print "<div style='width:100%;color:red;text-align:center;'>Findings Deleted</div>";
                }
                ?>
                <div style="width: 600px; float: left; height: 35px;">
                  <?php if ($tgt_id) { ?>
                    <input type="button" class="button-delete" value="Delete" style="float: left;"
                           onclick="validateDelete();" />
                    <input type="button" style="float: left;" class="button-delete" value="Delete Findings"
                           onclick="validateDeleteFindings();" />
                         <?php } ?>
                </div>
                <div style="width: 600px; float: right; height: 35px;">
                  <?php if ($tgt_id) { ?>
                    <input type='button' class='button' value='Export CKL' onclick='javascript:export_ckl(null, <?php print $tgt_id; ?>);' />
                    <input type="button" class="button" value="Merge Target" onclick="javascript:merge_target();" />
                    <input type='button' class="button" value="Upload" onclick="javascript:open_upload();" />
                  <?php } ?>
                  <input type='button' class="button" value="Save" onclick="javascript:validateTargetForm();" />
                  <input type='button' class="button" value="Cancel" onclick="window.location.href = 'index.php';" />
                </div>
                <!-- BASIC INFORMATION -->
                <div style="Float: left;">
                  <table class="Border" style="width: 590px;">
                    <thead>
                      <tr>
                        <th class="Text" colspan="2">Basic Information</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td style="padding-top: 10px;"><?php print $required; ?>ST&amp;E Name:</td>
                        <td class="Control">
                          <?php
                          if ($tgt_id) {
                            print "<label class='label'>{$ste->get_System()->get_Name()}, {$ste->get_Site()->get_Name()}, {$ste->get_Eval_Start_Date()->format("d M Y")}</label>";
                            print "<input type='hidden' name='ste' value='{$ste_id}' />";
                          }
                          else {
                            ?>
                            <select name="ste" class="Control">
                              <?php print $db->get_STE_List(); ?>
                            </select>
                            <label class="ErrorMsg" id="validateSTE" style="display: none;"></label>
                          <?php } ?>
                        </td>
                      </tr>
                      <tr>
                        <td><?php print $required; ?>Class</td>
                        <td class="Control"><select
                            name="Classification" class="Control">
                            <option value="0">-- Select Classification --</option>
                            <option value="U" <?php print $tgt_id && $tgt->classification == 'U' ? "selected" : ''; ?>>Public/UNCLASSIFED</option>
                            <option value="FOUO" <?php print $tgt_id && $tgt->classification == 'FOUO' ? "selected" : ''; ?>>Sensitive/FOUO</option>
                            <option value="S" <?php print $tgt_id && $tgt->classification == 'S' ? "selected" : ''; ?>>Classified/SECRET</option>
                          </select></td>
                      </tr>
                      <tr>
                        <td><?php print $required; ?>Name:</td>
                        <td class="Control">
                          <input type="text" id="DeviceName" name="DeviceName"
                                 class="Control Space" value="<?php print $tgt_id ? $tgt->get_Name() : ''; ?>" />
                          <label class="ErrorMsg" id="validateDeviceName" style="display: none;"></label>
                        </td>
                      </tr>
                      <tr>
                        <td><?php print $required; ?>OS:</td>
                        <td class="Control" style="text-align: left; width: 470px;">
                          <input type='text' id='os_filter' title='CPE string'
                                 placeholder='Filter...' onkeyup="javascript:filter_os();"
                                 autocomplete="off" />
                          <span id="osSoftware">
                            <?php
                            if ($tgt_id) {
                              print "{$tgt->get_OS_String()}<input type='hidden' name='osSoftware' id='os_id' value='{$tgt->get_OS_ID()}' />";
                            }
                            else {
                              print "<input type='hidden' name='osSoftware' id='os_id' />";
                            }
                            ?>
                          </span>
                          <div id="availableOS" onmouseover="$(this).show();" onmouseout="$(this).hide();"
                               style="display: none;">
                          </div>
                          <label class="ErrorMsg" id="validateOS" style="display: none;"></label>
                        </td>
                      </tr>
                      <tr>
                        <td>Location:</td>
                        <td class="Control">
                          <input id="location" name="location" class="Control Space"
                                 value="<?php print $tgt_id ? $tgt->get_Location() : ''; ?>" />
                        </td>
                      </tr>
                      <tr>
                        <td colspan="2">
                          <table style="width: 100%;">
                            <tbody>
                              <tr>
                                <td>Automated:</td>
                                <td class="Control">
                                  <select name="automated_taskStatus" class="Control">
                                    <?php
                                    $status_id = 5;
                                    if ($tgt_id) {
                                      $status_id = $tgt->get_Auto_Status_ID() ? $tgt->get_Auto_Status_ID() : 5;
                                    }

                                    foreach ($task_status as $key => $val) {
                                      $selected = $key == $status_id ? " selected" : '';
                                      print "<option value='$key'$selected>$val</option>";
                                    }
                                    ?>
                                  </select>
                                </td>
                                <td class="Label">Manual:</td>
                                <td class="Control">
                                  <select name="manual_taskStatus" class="Control">
                                    <?php
                                    $status_id = 5;
                                    if ($tgt_id) {
                                      $status_id = $tgt->get_Man_Status_ID() ? $tgt->get_Man_Status_ID() : 5;
                                    }

                                    foreach ($task_status as $key => $val) {
                                      $selected = $key == $status_id ? " selected" : '';
                                      print "<option value='$key'$selected>$val</option>";
                                    }
                                    ?>
                                  </select>
                                </td>
                              </tr>
                              <tr>
                                <td>Data:</td>
                                <td class="Control">
                                  <select name="dataGathering_taskStatus" class="Control">
                                    <?php
                                    $status_id = 5;
                                    if ($tgt_id) {
                                      $status_id = $tgt->get_Data_Status_ID() ? $tgt->get_Data_Status_ID() : 5;
                                    }

                                    foreach ($task_status as $key => $val) {
                                      $selected = $key == $status_id ? " selected" : '';
                                      print "<option value='$key'$selected>$val</option>";
                                    }
                                    ?>
                                  </select>
                                </td>
                                <td>FP/CAT I:</td>
                                <td class="Control">
                                  <select name="fp_CAT1_taskStatus" class="Control">
                                    <?php
                                    $status_id = 5;
                                    if ($tgt_id) {
                                      $status_id = $tgt->get_FP_Cat1_Status_ID() ? $tgt->get_FP_Cat1_Status_ID() : 5;
                                    }

                                    foreach ($task_status as $key => $val) {
                                      $selected = $key == $status_id ? " selected" : '';
                                      print "<option value='$key'$selected>$val</option>";
                                    }
                                    ?>
                                  </select>
                                </td>
                              </tr>
                            </tbody>
                          </table>
                        </td>
                      </tr>
                      <tr>
                        <td colspan="2">
                          <div style="float: left; margin-left: 15px; text-align: left;">
                            Available Checklists:
                            <input type='text' name='chk_filter' id='chk_filter'
                                   onkeyup="javascript:filter_checklists($('#hide_old').is(':checked'));"
                                   style='width: 132px;' /><br />
                            <select class="Control" name="availableChecklists" id="availableChecklists" multiple size="9" style="width: 250px;">
                              <?php
                              $chklst = $db->get_Checklist();
                              if ($tgt_id && count($tgt->checklists)) {
                                foreach ($chklst as $key => $checklist) {
                                  if ($checklist->get_Name() != 'Orphan') {
                                    if (!in_array($checklist, $tgt->checklists)) {
                                      print $checklist->print_Option();
                                    }
                                  }
                                }
                              }
                              else {
                                foreach ($chklst as $key => $checklist) {
                                  if ($checklist->get_Name() != 'Orphan') {
                                    print $checklist->print_Option();
                                  }
                                }
                              }
                              ?>
                            </select>
                          </div>
                          <div
                            style="float: left; margin: 15px 15px 5px; padding-top: 10px;">
                            <img alt="Add One" title="Add One" src="/img/ico_right-arrow.png"
                                 onclick="javascript:moveItems('availableChecklists', 'applicableChecklists');">
                            <br />
                            <img alt="Remove One" title="Remove One" src="/img/ico_left-arrow.png"
                                 onclick="javascript:moveItems('applicableChecklists', 'availableChecklists');">
                            <br />
                            <img alt="Remove All" title="Remove All" src="/img/ico_double-arrow-left.png"
                                 onclick="javascript:moveAll('applicableChecklists', 'availableChecklists');">
                          </div>
                          <div style="text-align: left;">
                            Applicable Checklists:<br />
                            <select class="Control" name="applicableChecklists[]"
                                    id="applicableChecklists" multiple
                                    size="9" style="width: 250px;">
                                      <?php
                                      if ($tgt_id && count($tgt->checklists)) {
                                        foreach ($tgt->checklists as $key => $check) {
                                          if ($check->get_Name() != 'Orphan') {
                                            print $check->print_Option();
                                          }
                                        }
                                      }
                                      ?>
                            </select>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td style='text-align: left; padding-left: 15px;'>
                          <label for='hide_old'>Hide Old</label>
                          <input type='checkbox' name='hide_old' id='hide_old' value='1' checked
                                 onclick="javascript:filter_checklists($(this).is(':checked'));" />
                        </td>
                        <td style='text-align: left; padding-left: 202px;'>
                          <label for='suspend_pp'>Suspend Post-processing</label>
                          <input type='checkbox' name='suspend_pp' id='suspend_pp' value='1'
                                 <?php print $tgt_id && $tgt->is_PP_Suspended() ? 'checked' : ''; ?> /><br />
                        </td>
                      </tr>
                      <tr>
                        <td>Notes:</td>
                        <td class="Control" style="padding-bottom: 30px;">
                          <textarea name="targetNotes" class="Control"
                                    style="vertical-align: top;" rows="6"
                                    cols="52"><?php print $tgt_id ? $tgt->get_Notes() : ''; ?></textarea>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <!-- TARGET DETAILS -->
                <div style="float: right;">
                  <?php if ($tgt_id) { ?>
                    <table id="software" class="Border" style="width: 595px;">
                      <thead>
                        <tr>
                          <th class="Text" colspan="2">Target Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td colspan="2">
                            <div style="float: left; margin-left: 30px; text-align: left;">
                              Available Software:
                              <input type='text' name='sw_filter' id='sw_filter' title='CPE string'
                                     onkeyup='(this.value.length >= 3 ? filter_software() : $("#availableSoftware").html(""));'
                                     style='width: 127px;' />
                              <br />
                              <div id='availableSoftware'></div>
                            </div>
                            <div style="float: left; margin: 15px 15px 5px; padding-top: 10px;">
                              <img alt="Remove One" title="Remove One" src="/img/ico_left-arrow.png"
                                   onclick="javascript:moveItems('installedSoftware');">
                            </div>
                            <div style="text-align: left;">Installed Software:<br />
                              <select class="Control" name="installedSoftware[]" id="installedSoftware" multiple size="15"
                                      style="width: 240px; height: 227px;">
                                        <?php
                                        if ($tgt_id && count($tgt->software)) {
                                          foreach ($tgt->software as $key => $software) {
                                            print $software->print_Option();
                                          }
                                        }
                                        ?>
                              </select>
                            </div>
                          </td>
                        </tr>
                        <tr>
                          <td style="text-align: left; width: 70px; padding: 8px 0 0 10px; line-height: 20px;">Missing<br />Patches:</td>
                          <td class="Control">
                            <textarea name="missingPatches" class="Control" style="vertical-align: top; margin-top: 10px; width: 475px; height: 125px; white-space: nowrap; overflow-x: scroll;">
                              <?php print $tgt_id ? $tgt->get_Missing_Patches() : ''; ?>
                            </textarea>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 0 0 0 10px; text-align: left; line-height: 20px;">Netstat<br />Connections:</td>
                          <td class="Control">
                            <textarea name="netstatConnections" class="Control" style="vertical-align: top; width: 475px; height: 125px; white-space: nowrap; overflow-x: scroll;">
                              <?php print $tgt_id ? $tgt->get_Netstat_Connections() : ''; ?>
                            </textarea>
                          </td>
                        </tr>
                        <tr>
                          <td>Login:</td>
                          <td class="Control" style="padding-bottom: 14px;">
                            <input name="login" class="Control Space" value="<?php print $tgt_id ? $tgt->get_Login() : ''; ?>" />
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  <?php } ?>
                </div>
                <!-- PORTS/PROTOCOLS $ SERVICES -->
                <div style="float: right;">
                  <?php if ($tgt_id) { ?>
                    <p class="Text Head">
                      Ports / Protocols &amp; Services
                      <input type="button" name="add_interface" id="add_interface" value="Add Interface"
                             style="float: right;" />
                    </p>
                    <div id="msg" style="display: none;">
                      <span style="float: left; font-weight: bold; color: red;">* Proper IPv4 Format Required</span>
                    </div>
                    <table id="iPs" class="Border" style="margin-top: 5px; width: 1200px;">
                      <thead>
                        <tr>
                          <th class="header" style="width: 110px;">IP</th>
                          <th class="header" style="width: 220px;">Host Name</th>
                          <th class="header" style="width: 220px;">Interface</th>
                          <th class="header" style="width: 220px;">FQDN</th>
                          <th class="header" style="width: 380px;">Description</th>
                        </tr>
                      </thead>
                      <tbody id="Interface">
                        <?php
                        if ($tgt_id) {
                          $odd = true;
                          foreach ($tgt->interfaces as $intface) {
                            if ($intface->get_IPv4() != '0.0.0.0' && $intface->get_IPv6() != '::') {
                              print $intface->get_Table_Data($odd);
                              // This flips the bool everytime it loops
                              // This is for odd and even row colors
                              $odd = !$odd;
                            }
                          }
                        }
                        ?>
                      </tbody>
                    </table>
                    <script>
                      $odd = <?php print json_encode($odd); ?>;
                      $int_id = <?php print $db->get_Last_Interface_ID() + 1; ?>
                    </script>
                    <div id="portsProtocol" class="Border" style="margin: 10px 0px 10px; width: 1200px;">
                      <div>
                        <span class="header pps">Port / Protocol</span>
                        <span class="header listen">Listening</span>
                        <span class="header iana-name">IANA Name</span>
                        <span class="header banner">Banner</span>
                        <span class="header pps-notes">Notes</span>
                      </div>
                      <?php
                      if ($tgt_id) {
                        $ports = array();
                        $odd = true;

                        foreach ($tgt->interfaces as $intface) {
                          try {
                            $tcp_ports = $intface->get_TCP_Ports();
                            $udp_ports = $intface->get_UDP_Ports();
                          }
                          catch (Exception $e) {

                          }

                          if ($tcp_ports != null) {
                            foreach ($tcp_ports as $key => $tcp) {
                              $port_num = str_pad($tcp->get_Port(), 5, '0', STR_PAD_LEFT);
                              $ports[$port_num . '/tcp/' . $intface->get_ID()] = array(
                                'intid' => $intface->get_ID(),
                                'ip'    => ($intface->get_IPv4() ? $intface->get_IPv4() : $intface->get_IPv6()),
                                'port'  => $tcp
                              );
                            }
                          }
                          if ($udp_ports != null) {
                            foreach ($udp_ports as $key => $udp) {
                              $port_num = str_pad($udp->get_Port(), 5, '0', STR_PAD_LEFT);
                              $ports[$port_num . '/udp/' . $intface->get_ID()] = array(
                                'intid' => $intface->get_ID(),
                                'ip'    => ($intface->get_IPv4() ? $intface->get_IPv4() : $intface->get_IPv6()),
                                'port'  => $udp
                              );
                            }
                          }
                        }

                        ksort($ports, SORT_STRING);

                        foreach ($ports as $key => $port) {
                          print $port['port']->get_Table_Data($port['ip'], $port['intid'], $odd);

                          $odd = !$odd;
                        }
                      }
                      ?>
                    </div>
                  <?php } ?>
                </div>
              </div>
            </div>
            <!-- BUTTONS -->
            <div style="width: 600px; float: left;">
              <?php if ($tgt_id) { ?>
                <input type="button" class="button-delete" value="Delete" style="float: left;"
                       onclick="validateDelete();" />
                     <?php } ?>
            </div>
            <div style="width: 600px; float: right;">
              <?php if ($tgt_id) { ?>
                <input type=button class="button" value="Upload"
                       onclick="javascript:open_upload();" />
                     <?php } ?>
              <input type=button class="button" value="Save"
                     onclick="javascript:validateTargetForm();" />
              <input type=button class="button" value="Cancel"
                     onclick="window.location.href = 'index.php?ste=<?php print ($ste_id ? $ste_id : ''); ?>';" />
            </div>
          </div>
        </div>
      </div>
    </form>
  </div>
</div>
<div class="backdrop"></div>
<?php
if ($tgt_id) {
  ?>
  <div id='merge_target' class='box'>
    Primary target: <?php print ($tgt_id ? $tgt->get_Name() : null); ?><br />
    <form method="post" action="target.php">
      <input type="hidden" name="ste" value="<?php print $ste_id; ?>" />
      <input type="hidden" name="tgt" value="<?php print ($tgt_id ? $tgt_id : 0); ?>" />
      Secondary target:
      <select name="sec_tgt">
        <option>-- Select Target --</option>
        <?php
        $tgts = $db->get_Target_Details($ste_id);
        if (is_array($tgts) && count($tgts) && isset($tgts['id'])) {
          $tgts = array(0 => $tgts);
        }
        if (is_array($tgts) && count($tgts) && isset($tgts[0]) && is_a($tgts[0], 'target')) {
          foreach ($tgts as $t) {
            if ($t->get_ID() != $tgt->get_ID())
              print "<option value='{$t->get_ID()}'>{$t->get_Name()}</option>";
          }
        }
        ?>
      </select><br />
      <input type="submit" name="merge_target" value="Submit" />
    </form>
  </div>
  <div id='upload_div' class='box'>
    <form class="dropzone" action="/upload.php" id="dropzone">
      <div class="fallback">
        <input type="file" name="file" multiple />
      </div>
    </form>

    <form method='post' action='target.php'>
      <input type='hidden' name='action' value='data_collection' />
      <input type='hidden' name='ste' value='<?php print $ste_id ? $ste_id : 0; ?>' />
      <input type='hidden' name='tgt' value='<?php print $tgt_id ? $tgt_id : 0; ?>' />
      <label for='overwrite'>Overwrite existing answer file?</label>
      <input type='checkbox' name='overwrite' value='1' />
      <input type='submit' name='submit' value='Parse Host Data Collection' />
    </form>

    <?php
    check_path(TMP . "/data_collection/{$tgt->get_Name()}");
    $answer_file = glob(realpath(TMP . "/data_collection/{$tgt->get_Name()}") . "/*-answers.txt");

    if (count($answer_file) > 1) {
      print "<div style='color:red;'>WARNING: More than one answer file is present, please reconcile before proceeding</div><br />";
    }
    if (count($answer_file)) {
      print "<div style='color:red;'>Answer file is already present ({$answer_file[0]})</div><br />";

      $answers = file($answer_file[0]);
      foreach ($answers as $answer) {
        print "$answer<br />";
      }
    }
    ?>
  </div>
  <?php
}
