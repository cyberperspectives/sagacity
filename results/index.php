<?php
/**
 * File: index.php
 * Author: Ryan Prather
 * Purpose: index page of the results
 * Created: Sep 16, 2013
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
 *  - Sep 16, 2013 - File created
 *  - Sep 1, 2016 - Copyright and file purpose updated
 *  - Oct 6, 2016 - Migrated upload progress page here
 *  - Oct 24, 2016 - Moved the delete_scan functionality earlier so the deleted scan doesn't appear in the scan list
 * 					 Added add_scan ajax function
 * 					 Updated update_script_status function to retrieve JSON instead of XML
 * 					 Updated several other areas in support of above
 *  - Nov 7, 2016 - Changed "List Hosts" and "Delete" buttons to images instead of wide buttons.
 *           Added Process kill button back in as well.
 *  - Nov 18, 2016 - Fixed error when no ST&E is selected
 *  - Dec 7, 2016 - Fixed bug when updating script status
 *  - Dec 12, 2016 - Changed update_script_status function to restart if there was an error
 *  - Jan 30, 2017 - Formatting
 *  - Feb 15, 2017 - Cleaned up
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 *  - Mar 14, 2017 - Increased time limit for page load to 120 seconds, converted direct $_REQUEST to filter_input calls
 *  - Apr 5, 2017 - Removed Kill button if script is NOT 'RUNNING', fixed bug deleting result files,
 *                  Cleaned up code a little
 *  - May 13, 2017 - Migrated results table to DataTables instead of tablesorter library
 *  - May 19, 2017 - Unified button code, added check for NOTIFICATIONS constant before playing sound
 *  - May 20, 2017 - Changed header widths, added source image, and removed ordering for source and status columns
 *  - May 22, 2017 - UI fixes.  Fixed a couple bugs with new DataTables library, Refresh toggle, filtering, ordering.  Also fixed timeouts and slow responses (look at dev tools network tab)
 *  - May 26, 2017 - Fixed error with uploading image size being changed...oversight on my part.
 *  - Jul 13, 2017 - Fixed display of "null" when creating new result row
 *  - Jan 16, 2018 - Formatting, updated to use host_list class, fixed bug with delete_Scan,
		Added /img/error.png to action column if there is any target with an error
		Changed scan deletion to an AJAX call, and changed confirmation boxes to use jQuery UI
 *  - Apr 19, 2018 - Updated 3rd party libraries
 *  - Jun 2, 2018 - Fixed bug with kill image not displaying correctly
 */
$title_prefix = "Result Management";
include_once 'config.inc';
include_once 'header.inc';
include_once 'database.inc';
include_once 'import.inc';

set_time_limit(120);

$db = new db();

$ste_id = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT);
if (! $ste_id) {
    $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT);
}
$status = filter_input(INPUT_POST, 'status', FILTER_SANITIZE_STRING);
$type = filter_input(INPUT_POST, 'type', FILTER_SANITIZE_STRING);
$scans = [];

if ($type != 'all' && $status != 'all') {
    $scans = $db->get_ScanData($ste_id, null, $status, $type);
} elseif ($type != 'all') {
    $scans = $db->get_ScanData($ste_id, null, null, $type);
} elseif ($status != 'all') {
    $scans = $db->get_ScanData($ste_id, null, $status);
} elseif (isset($ste_id)) {
    $scans = $db->get_ScanData($ste_id);
}

$stes = $db->get_STE();

?>


<!--  add in page style tags for Results page size -->
<style type="text/css">
.scan_type {
	width: 25px;
}

#importBtn {
	margin: auto;
	width: 1200px;
	text-align: right;
}

#host_list_frame {
	width: 100%;
	height: 100%;
}

#progress p {
	width: 1000px;
}

/* Results Management list host button */
.button-list {
	display: inline-block;
	outline: 0;
	white-space: nowrap;
	background: #A4C1DD;
	box-shadow: inset 0px 0px 0px 1px #192364, 0px 2px 3px 0px
		rgba(0, 0, 0, 0.25);
	border: solid 1px #102D5F;
	border-radius: 6px;
	background-image: -moz-linear-gradient(top, #A4C1DD, #1D57A0);
	background-image: -webkit-linear-gradient(top, #A4C1DD, #1D57A0);
	background-image: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#A4C1DD),
		to(#1D57A0));
	background-image: -ms-linear-gradient(top, #A4C1DD, #1D57A0);
	background-image: -o-linear-gradient(top, #A4C1DD, #1D57A0);
	background-image: linear-gradient(top, #A4C1DD, #1D57A0);
	text-decoration: none;
	text-shadow: -1px -1px 0 rgba(0, 0, 0, 0.5);
	font-size: 12pt;
	color: #fff;
	font-family: 'Yanone Kaffeesatz';
	width: 70px;
	height: 30px;
}

/* Button mouseover Activity for scan table */
.mouseover-scan {
	background: #E55234;
	box-shadow: inset 0px 0px 0px 1px #F5AC97, 0px 2px 3px 0px
		rgba(0, 0, 0, 0.25);
	border: solid 1px #B72204;
	border-radius: 6px;
	background-image: -moz-linear-gradient(top, #B41D08, #EB6541);
	background-image: -webkit-linear-gradient(top, #B41D08, #EB6541);
	background-image: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#B41D08),
		to(#EB6541));
	background-image: -ms-linear-gradient(top, #B41D08, #EB6541);
	background-image: -o-linear-gradient(top, #B41D08, #EB6541);
	background-image: linear-gradient(top, #B41D08, #EB6541);
}

td span {
	display: none;
}

.checklist_image {
	width: 32px;
	vertical-align: middle;
}
</style>

<script type='text/javascript'>
    var to;
    var table;
    var button;
<?php if (NOTIFICATIONS && file_exists("complete.mp3")) { ?>
        var audio = new Audio("complete.mp3");
<?php } ?>
    $(function () {
      to = setTimeout(update_script_status, <?php print UPDATE_FREQ * 1000; ?>);
      table = $('#results-table').DataTable({
        'columnDefs': [{'orderable': false, 'targets': [2, 5]}],
        'stripeClasses': ['odd_row', 'even_row'],
        'pageLength': 25
      });
      table.columns().flatten().each(function (colIdx) {
        if (colIdx === 2) {
          $('#type').change(function () {
            table
                    .column(2)
                    .search($(this).val())
                    .draw();
          });
        }
        else if (colIdx === 5) {
          $('#status').change(function () {
            table
                    .column(5)
                    .search($(this).val())
                    .draw();
          });
        }
      });
      $('.button,.button-delete,.button-list').mouseover(function () {
        $(this).addClass('mouseover-scan');
      });
      $('.button,.button-delete,.button-list').mouseout(function () {
        $(this).removeClass('mouseover-scan');
      });
    });
    /**
     *
     */
    function update_script_status() {
      $.ajax('/ajax.php', {
        data: {
          action: 'update_script_status',
          ste: <?php print isset($ste_id) ? $ste_id : 0; ?>,
          status: $('#status').val(),
          'type': $('#type').val()
        },
        success: function (data) {
          if (data.error) {
            console.error(data.error);
            return;
          }
          to = null;
          for (var x in data.results) {
            var kill = '';
            var scan_id = data.results[x].scan_id;
            var row = table.row('#id-' + scan_id);
            if(row.length) {
              var idx = row.index();
              tmp = row.data();
              var cur_status = tmp[5];
              tmp[4] = data.results[x].run_time;
              tmp[5] = data.results[x].status;
              tmp[6] = "<progress min='0' max='100' value='" + data.results[x].perc_comp + "' title='" + data.results[x].perc_comp + "%'></progress><span>" + data.results[x].perc_comp + "</span>";
              kill = $('#action-' + scan_id + ' .kill');
              if (data.results[x].status === 'RUNNING' && !kill.length) {
                tmp[7] += "<a class='kill-link' href='kill.php?ste=<?php print $ste_id; ?>&id=" + scan_id + "&pid=" + data.results[x].pid + "' target='_blank'>" +
                        "<img class='kill checklist_image' src='/img/X.png' style='vertical-align:middle;' title='Kill' />" +
                        "</a>";
              }
              else if (cur_status === 'RUNNING' && data.results[x].status === 'COMPLETE') {
                $('#action-' + scan_id + '.kill-link').remove();
<?php if (NOTIFICATIONS && file_exists("complete.mp3")) { ?>
                audio.play();
<?php } ?>
              }
              table.row(idx).invalidate(tmp).draw(false);
            }
            else {
              if ($('#status').val() && $('#type').val()) {
                if ($('#status').val() !== data.results[x].status ||
                        $('#type').val() !== data.results[x].source) {
                  continue;
                }
              }
              else if ($('#status').val()) {
                if ($('#status').val() !== data.results[x].status) {
                  continue;
                }
              }
              else if ($('#type').val()) {
                if ($('#type').val() !== data.results[x].source) {
                  continue;
                }
              }

              var row = $('<tr id="id-' + scan_id + '"></tr>');
              row.append("<td title='" + data.results[x].notes + "'>" + data.results[x].file_name + "</td>");
              row.append("<td>" + data.results[x].file_date + "</td>");
              row.append("<td class='dt-body-center'>" +
                      "<img class='scan_type' src='/img/scan_types/" + data.results[x].source_img + "' title='" + data.results[x].source + "' /><br />" +
                      "<span>" + data.results[x].source + "</span>" +
                      "</td>");
              row.append("<td>" + data.results[x].start_time + "</td>");
              row.append("<td>" + data.results[x].run_time + "</td>");
              row.append("<td>" + data.results[x].status + "</td>");
              row.append("<td><progress min='0' max='100' value='" + data.results[x].perc_comp + "'></progress><span>" + data.results[x].perc_comp + "</span></td>");
              if (data.results[x].status === 'RUNNING') {
                kill = "<a href='kill.php?ste=<?php print $ste_id; ?>&id=" + scan_id + "&pid=" + data.results[x].pid + "' target='_blank'>" +
                        "<img class='kill checklist_image' src='/img/X.png' style='vertical-align:middle;' title='Kill' />" +
                        "</a>";
              }
              row.append("<td class='dt-body-center' id='action-" + scan_id + "'>" +
                      (data.results[x].error ? "<img src='/img/error.png' class='checklist_image' onclick='javascript:List_host(" + scan_id + ");' />" : "") +
                      "<a href='javascript:void(0);' title='Host Listing' onclick='javascript:List_host(" + scan_id + ");'><img src='/img/options.png' class='checklist_image' /></a>&nbsp;" +
                      "<img src='/img/delete.png' class='checklist_image' " +
                        "onclick='scan_id=" + scan_id + ";del_scan($(this));' " +
                        "title='Delete a scan file' />"
                      + kill
                      );
              table.row.add(row[0]);
            }
          }

          table.order(table.order()[0]).draw(false);
          $('.button-delete,.button-list').mouseover(function () {
            $(this).addClass('mouseover-scan');
          });
          $('.button-delete,.button-list').mouseout(function () {
            $(this).removeClass('mouseover-scan');
          });
          if ($('#toggle_refresh').val() === 'Stop Refresh' && (!$('#delete-target-confirm').dialog('isOpen') || !$('#delete-scan-confirm').dialog('isOpen'))) {
            to = setTimeout(update_script_status, <?php print UPDATE_FREQ * 1000; ?>);
          }
        },
        error: function (xhr, status, error) {
          if ($('#toggle_refresh').val() === 'Stop Refresh') {
            to = setTimeout(update_script_status, <?php print UPDATE_FREQ * 1000; ?>);
          }
        },
        dataType: 'json',
        //timeout: 5000,
        method: 'post'
      });
    }
    /**
     *
     */
    function toggle_refresh() {
      if ($('#toggle_refresh').val() === 'Stop Refresh') {
        clearTimeout(to);
        $('#toggle_refresh').val('Start Refresh');
        to = null;
      }
      else {
        to = setTimeout(update_script_status, <?php print UPDATE_FREQ * 1000; ?>);
        $('#toggle_refresh').val('Stop Refresh');
      }
    }
</script>
<script src="results_script.min.js" type="text/javascript"></script>
<script src='/script/datatables/DataTables-1.10.9/js/jquery.dataTables.min.js'></script>
<link rel="stylesheet" href="/script/datatables/DataTables-1.10.9/css/jquery.dataTables.min.css" />
<link rel='stylesheet' href='/script/jquery-ui/jquery-ui.min.css' />

<div id='wrapper'>
    <div id='main-wrapper'>
        <div class='12u' id='main-content'>
            <div class="5grid-layout" style="text-align: right;">
                <div class="row">
                    <div class="12u">
                        <div style='float: left; margin-top: 6px;'>
                            <form method="post" action="index.php">
                                ST&amp;E Name:
                                <select name='ste' style='width: 400px;' id="ste"
                                    onchange="setCookie('ste', this.value);this.form.submit();">
                                    <option value='0'>-- Please Select an ST&amp;E --</option>
                                    <?php
                                    if (is_array($stes) && count($stes)) {
                                        foreach ($stes as $ste) {
                                            print "<option value='{$ste->get_ID()}'" .
                                                ($ste_id && $ste_id == $ste->get_ID() ? " selected" : "") .
                                                ">" .
                                                "{$ste->get_System()->get_Name()}, {$ste->get_Site()->get_Name()}, {$ste->get_Eval_Start_Date()->format("d M Y")}" .
                                                "</option>";
                                        }
                                    }

                                    ?>
                                </select>
                            </form>
                        </div>
                        <div id="importBtn">
                            <!-- Results tab Import Button -->
                            <input type='button' class="button"
                                value='Stop Refresh' id="toggle_refresh"
                                onclick="javascript:toggle_refresh();" />
                            <input type='button' class='button'
                                value='Import'
                                onclick="javascript:add_import();" />
                        </div>
                    </div>
                </div>
            </div>

            <div style='margin: 20px auto auto auto; width: 1200px;'>
                <table id="results-table" class='display compact hover'
                    data-page-length='25'>
                    <thead>
                        <tr>
                            <th style='width: 325px;'>Name</th>
                            <th style='width: 75px;'>Date</th>
                            <th style='width: 65px;'>
                                <select id='type' style='width: 60px;'>
                                    <option value=''>TYPE</option>
                                    <option>Data Collection</option>
                                    <option>eChecklist</option>
                                    <option>Gold Disk</option>
                                    <option>MBSA</option>
                                    <option>MSSQL</option>
                                    <option>Nessus</option>
                                    <option>NMAP</option>
                                    <option>Retina</option>
                                    <option>SCC XCCDF</option>
                                    <option>SRR</option>
                                    <option>STIG Viewer</option>
                                </select>
                            </th>
                            <th style='width: 65px;'>Start</th>
                            <th>Running</th>
                            <th style='width: 80px;'>
                                <select id='status' style='width: 75px;'>
                                    <option value=''>STATUS</option>
                                    <option>IN QUEUE</option>
                                    <option>RUNNING</option>
                                    <option>COMPLETE</option>
                                    <option>ERROR</option>
                                    <option>TERMINATED</option>
                                </select>
                            </th>
                            <th>% Comp</th>
                            <th>Action&nbsp;&nbsp;
                                <a href="kill.php?pid=*&ste=<?php print (isset($ste_id) ? $ste_id : '0'); ?>"
                                    target='_new'>
                                    <img src='/img/X.png' class='checklist_image'
                                        style='vertical-align: middle;'
                                        title='Kill and Remove All' />
                                </a>
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        if (isset($ste_id) && $ste_id > 0) {
                            foreach ($scans as $scan) {
                                $diff = $scan->get_Last_Update()->diff($scan->get_Start_Time());

                                ?>
                        <tr id='<?php print "id-{$scan->get_ID()}"; ?>'>
                            <td title='<?php print $scan->get_Notes(); ?>'><?php print $scan->get_File_Name(); ?></td>
                            <td><?php print $scan->get_File_DateTime()->format("Y-m-d"); ?></td>
                            <td class='dt-body-center'>
                                <img class='scan_type' src='/img/scan_types/<?php print $scan->get_Source()->get_Icon(); ?>'
                                    title='<?php print $scan->get_Source()->get_Name(); ?>' /><br />
                                <span><?php print $scan->get_Source()->get_Name(); ?></span>
                            </td>
                            <td><?php print $scan->get_Start_Time()->format("y-m-d H:i:s"); ?></td>
                            <td><?php print (!is_null($diff) ? $diff->format("%H:%I:%S") : ""); ?></td>
                            <td><?php print $scan->get_Status(); ?></td>
                            <td>
                                <progress min='0' max='100'
                                    value='<?php print $scan->get_Percentage_Complete(); ?>'
                                    title='<?php print $scan->get_Percentage_Complete(); ?>%'></progress>
                                <span><?php print $scan->get_Percentage_Complete(); ?></span>
                            </td>
                            <td class='dt-body-center' id="action-<?php print $scan->get_ID(); ?>">
                                <?php if ($scan->isScanError()) { ?>
                                    <img src='/img/error.png' class='checklist_image'
                                        onclick='javascript:List_host(<?php print $scan->get_ID(); ?>);' />&nbsp;
                                <?php } ?>
                                <a href='javascript:void(0);' title='Host Listing'
                                    onclick='javascript:List_host(<?php print $scan->get_ID(); ?>);'>
                                    <img src='/img/options.png' class='checklist_image'
                                        title='See what hosts are on this target' />
                                </a>&nbsp;
                                <img src='/img/delete.png' class='checklist_image'
                                    onclick='scan_id=<?php print $scan->get_ID(); ?>;del_scan($(this));'
                                    title='Delete a scan file' />
                                <?php if ($scan->get_Status() == 'RUNNING') { ?>
                                    <a class='kill-link' target='_blank'
                                        href='kill.php?<?php print "ste={$ste_id}&id={$scan->get_ID()}&pid={$scan->get_PID()}"; ?>'>
                                        <img src='/img/X.png' class='kill checklist_image'
                                            style='vertical-align: middle;' title='Kill' />
                                    </a>
                                <?php } ?>
                            </td>
                        </tr>
                                <?php
                            }
                        }

                        ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<div class="backdrop"></div>

<script type='text/javascript'>
    var delete_targets = false;
    var scan_id = 0;
    $(function () {
      $('.button-delete,.button-list').mouseover(function () {
        $(this).addClass('mouseover-scan');
      });
      $('.button-delete,.button-list').mouseout(function () {
        $(this).removeClass('mouseover-scan');
      });

      $('#delete-target-confirm').on('dialogclose', function(e) {
        if ($('#toggle_refresh').val() === 'Stop Refresh' && !$('#delete-scan-confirm').dialog('isOpen')) {
          to = setTimeout(update_script_status, <?php print UPDATE_FREQ * 1000; ?>);
        }
      });

      $('#delete-scan-confirm').on('dialogclose', function(e) {
        if ($('#toggle_refresh').val() === 'Stop Refresh') {
          to = setTimeout(update_script_status, <?php print UPDATE_FREQ * 1000; ?>);
        }
      });

      $('#delete-target-confirm').dialog({
        autoOpen: false,
        resizable: false,
        height: 'auto',
        width: 500,
        modal: true,
        buttons: {
          'Delete Targets': function () {
            delete_targets = true;
            $('#delete-scan-confirm').dialog('open');
            $(this).dialog('close');
          },
          'No': function () {
            delete_targets = false;
            $('#delete-scan-confirm').dialog('open');
            $(this).dialog('close');
          }
        },
        open: function() {
        	$(this).parent().find('.ui-dialog-buttonpane button:eq(1)').focus();
        }
      });

      $('#delete-scan-confirm').dialog({
        autoOpen: false,
        resizable: false,
        height: 'auto',
        width: 500,
        modal: true,
        buttons: {
          'Delete Scan': function () {
            $.ajax('/ajax.php', {
              data: {
                action: 'delete-scan',
                ste: $('#ste').val(),
                'scan-id': scan_id,
                'delete-targets': delete_targets
              },
              success: function (data) {
                if (data.error) {
                  alert(data.error);
                }
                else if (data.success) {
                  table.row($(button).closest('tr').index()).remove().draw();
                  $('#id-' + scan_id).remove();
                }
              },
              error: function (xhr, status, error) {
                console.error(error);
              },
              dataType: 'json',
              method: 'post'
            });

            $(this).dialog('close');
          },
          Cancel: function () {
            $(this).dialog('close');
          }
        },
        open: function() {
        	$(this).parent().find('.ui-dialog-buttonpane button:eq(1)').focus();
        }
      });
    });

    function del_scan(pressed_button) {
      if ($('#toggle_refresh').val() == 'Stop Refresh') {
        clearTimeout(to);
        to = null;
      }
      button = pressed_button;
      $('#delete-target-confirm').dialog('open');
    }
</script>

<div id='delete-target-confirm' title='Delete associated targets?'>
    <p>
        <span class='ui-icon ui-icon-alert'
            style='float: left; margin: 12px 12px 20px 0;'></span> Do
        you want to delete the associated targets?
    </p>
    <br />
    <p>WARNING: This will delete ALL targets in this scan and all
        associated data even if it was imported from another scan. This
        action is irreversible</p>
</div>

<div id='delete-scan-confirm' title='Delete this scan?'>
    <p>
        <span class='ui-icon ui-icon-alert'
            style='float: left; margin: 12px 12px 20px 0;'></span> Are
        you sure you want to delete this scan?
    </p>
</div>

<!-- code for list button -->
<div id="host_list_div" class="box">
    <iframe id="host_list_frame"></iframe>
</div>

<?php include_once '../import.php'; ?>

<?php
$add_scan = (boolean) filter_input(INPUT_GET, 'add_scan', FILTER_VALIDATE_BOOLEAN);
if ($add_scan) {
    print "<script type='text/javascript'>add_import();</script>";
}

include_once 'footer.inc';
