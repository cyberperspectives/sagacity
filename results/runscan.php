<?php
/**
 * File: runscan.php
 * Author: Ryan Prather
 * Purpose: This file is used to execute an automated scan from within the tool
 * Created: Jul 7, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jul 7, 2014 - File created
 */
$title_prefix = "Run Scan";
include_once 'database.inc';
include_once 'header.inc';

$db = new db();
?>

<script type="text/javascript">
  function show_scan(val) {
    $('#nmap').hide();

    if (val == "NMap") {
      $('#nmap').show();
    }
  }

  function run_scan(type) {
    $.ajax('/ajax.php', {
      data: {
        'action': 'run-scan',
        'type': type
      },
      success: function (data) {},
      error: function (xhr, status, error) {
        console.error(error);
      },
      datatype: 'json',
      timeout: 3000,
      method: 'post'
    });
  }
</script>

<style type="text/css">
  .scan_type {
    display:none;
  }
</style>

<div id="wrapper">
  <div id="main-wrapper">
    <div class="12u" id="main-content">
      <div class="modal"></div>
      <div class="5grid-layout" style="text-align: right;">
        <div class="row">
          <div class="12u" style="text-align:left;">
            ST&amp;E Name: <select name="ste" id="ste" class="Control" style="width:400px;" onchange="setCookie('ste', this.value);">
              <?php print $db->get_STE_List(); ?>
            </select>
          </div>
          <div class="12u" style="text-align: left;">
            Scan Type: <select name="type" class="Control" onchange="javascript:show_scan(this.value);">
              <option>-- Select scan type --</option>
              <option>NMap</option>
              <!-- <option>Nessus</option> -->
              <!-- <option>OpenVAS</option> -->
            </select>
          </div>
        </div>
        <div id="nmap" class="scan_type">
          <div style="border:solid 1px black;width:49%;float:left;text-align:left;padding-left:5px;">
            Name:<br />
            <input type="text" name="name" title="Used to name the result file" /><br />
            Included Targets:<br />
            <textarea name="in_networks" title="One host or network segment/line" rows="5" cols="50"></textarea><br />
            Excluded Targets:<br />
            <textarea name="ex_networks" title="One host or network segment/line&#10;Will automatically exclude this system" rows="5" cols="50"></textarea><br />
            Port List:<br />
            <textarea name="port_list" title="Single port, port range, or alias/line" rows="5" cols="50"></textarea><br />
          </div>
          <div style="border:solid 1px black;width:49%;float:right;text-align:left;padding-left:5px;">
            <label for="test">Label</label>
            <input type="checkbox" name="test" id="test" value="1" onclick="this.checked ? $('#name_text').show(); : $('#name_text').hide();" /><br />
            <div id="name_text" style="margin-left:25px;display:none;">
              <input type="text" name="name_text" /><br />
            </div>
          </div>
          <input type="button" name="submit" value="Run Scan" onclick='javascript:run_scan("nmap");' />
        </div>
        <!-- Nessus scan type (login info may be required) -->
        <div id="nessus" class="scan_type">
        </div>
      </div>
    </div>
  </div>
</div>

<?php
include_once 'footer.inc';
