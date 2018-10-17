<?php
/**
 * File: index.php
 * Author: Ryan Prather
 * Purpose: Main index page for the ST&E Operations
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
 *  - Sep 1, 2016 - Copyright and file purpose updated,
 * 					Added vertical menu
 *  - Oct 24, 2016 - Fixed a few display bugs
 *  - Nov 7, 2016 - Fixed more display bugs
 *  - Nov 21, 2016 - Added check for presents of scan sources before outputting them
 *  - Jan 30, 2017 - Formatting
 *  - Apr 5, 2017 - Removing rename category functionality and replacing with edit category,
 *                  Removed vertical menu code and CSS, removed commented out delete category lightbox,
 *                  STILL WORKING edit category code
 *  - Apr 7, 2017 - Completed edit category functionality
 *  - May 13, 2017 - Added Delete Host button (not functional yet)
 *                   Adding import scans popup (not complete)
 *  - May 19, 2017 - Simplified target selection code, added target deletion from OPs page, and changed buttons to match
 *  - May 26, 2017 - Added JS to delete hosts from category after deleting host using "Delete Host" button
 *  - May 30, 2017 - Fixed bug #209 error when saving category after editing
 *  - Jun 3, 2017 - Fixed bug #236
 *  - Apr 19, 2018 - Updated 3rd party libraries
 */
$title_prefix = "Operations";

include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

set_time_limit(0);

$db          = new db();
$cats        = [];
$action      = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$ste_id      = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$task_status = $db->get_Task_Statuses();
$stes        = $db->get_STE();
$scan_srcs   = $db->get_Sources();

if (!$ste_id) {
    $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}

if ($action) {
    if ($action == 'move_to') {
        $sel_tgts = json_decode(html_entity_decode(filter_input(INPUT_POST, 'selected_tgts', FILTER_SANITIZE_STRING)));
        $db->move_Tgt_To_Cat($sel_tgts, filter_input(INPUT_POST, 'move_to_cat', FILTER_VALIDATE_INT));
    }
    elseif ($action == 'save_cat') {
        $existing_cat = filter_input(INPUT_POST, 'selected_cat', FILTER_VALIDATE_INT);
        $new_cat_name = filter_input(INPUT_POST, 'new_cat_name', FILTER_SANITIZE_STRING);
        $analyst      = filter_input(INPUT_POST, 'analyst', FILTER_SANITIZE_STRING);
        $cat          = new ste_cat($existing_cat, $ste_id, $new_cat_name, $analyst);
        $sources      = filter_input(INPUT_POST, 'scan_sources', FILTER_VALIDATE_INT, FILTER_REQUIRE_ARRAY);

        if (is_array($sources) && count($sources)) {
            foreach ($sources as $src_id) {
                $cat->add_Source($db->get_Sources($src_id));
            }
        }

        $db->save_Category($cat);
    }
    elseif ($action == 'add_cat') {
        $name    = filter_input(INPUT_POST, 'new_cat', FILTER_SANITIZE_STRING);
        $sources = filter_input(INPUT_POST, 'scan_sources', FILTER_VALIDATE_INT, FILTER_REQUIRE_ARRAY);
        $ste_cat = new ste_cat(null, $ste_id, $name, null);

        if (is_array($sources) && count($sources)) {
            foreach ($sources as $idx => $id) {
                $ste_cat->add_Source($db->get_Sources($id));
            }
        }
        $db->save_Category($ste_cat);
    }
    elseif ($action == 'update_auto' || $action == 'update_manual' ||
        $action == 'update_data' || $action == 'update_fp_cat1') {
        $sel_tgts   = json_decode(html_entity_decode(filter_input(INPUT_POST, 'selected_tgts', FILTER_SANITIZE_STRING)));
        $new_status = filter_input(INPUT_POST, 'new_status', FILTER_SANITIZE_STRING);
        $db->update_Task_Status($action, $sel_tgts, $new_status);
    }
    elseif ($action == 'assign') {
        $cat_id  = filter_input(INPUT_POST, 'cat_id', FILTER_VALIDATE_INT);
        $analyst = filter_input(INPUT_POST, 'analyst', FILTER_SANITIZE_STRING);
        $db->assign_Analyst_To_Category($cat_id, $analyst);
    }
    elseif ($action == 'autocat') {
        $db->auto_Catorgize_Targets($ste_id);
    }
    elseif ($action == 'import_host_list') {
        $file = filter_input(INPUT_POST, 'file', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
        if (file_exists(TMP . "/$file")) {
            $fh     = fopen(TMP . "/$file", "r");
            $header = array_flip(array_map('strtolower', fgetcsv($fh)));
            if ((isset($header['hostname']) || isset($header['name'])) && isset($header['ip']) && isset($header['os']) && isset($header['category'])) {
                while ($row = fgetcsv($fh)) {
                    if (count($row) >= 4) {
                        $tgt_id = 0;
                        if (isset($header['name'])) {
                            $tgt_id = $db->check_Target($ste_id, $row[$header['name']]);
                        }

                        if (empty($tgt_id) && isset($header['hostname'])) {
                            $tgt_id = $db->check_Target($ste_id, $row[$header['hostname']]);
                        }

                        if (empty($tgt_id) && isset($row[$header['ip']])) {
                            foreach (explode(",", $row[$header['ip']]) as $ip) {
                                if ($tgt_id = $db->check_Target($ste_id, $ip)) {
                                    break;
                                }
                            }
                        }

                        if (!empty($tgt_id)) {
                            continue;
                            //$tgt = $db->get_Target_Details($ste_id, $tgt_id)[0];
                        }
                        else {
                            $tgt = new target((isset($header['name']) ? $row[$header['name']] : $row[$header['hostname']]));
                            $tgt->set_STE_ID($ste_id);
                        }

                        $os_regex = $db->get_Regex_Array('os');

                        if (substr($row[$header['os']], 0, 7) == 'cpe:2.3') {
                            $os = array(0 => new software(null, $row[$header['os']]));
                        }
                        elseif (substr($row[$header['os']], 0, 3) == 'cpe') {
                            $os = array(0 => new software($row[$header['os']], null));
                        }
                        else {
                            $os = software::identify_Software($os_regex, $row[$header['os']]);
                        }

                        $os = $db->get_Software($os);
                        if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
                            $tgt->set_OS_ID($os[0]->get_ID());
                            $tgt->set_OS_String($os[0]->get_Shortened_SW_String());
                        }
                        else {
                            $sw = new software("cpe:/o:generic:generic:-", "cpe:2.3:o:generic:generic:-:*:*:*:*:*:*");
                            $os = $db->get_Software($sw)[0];
                            $tgt->set_OS_ID($os->get_ID());
                            $tgt->set_OS_String($os->get_Shortened_SW_String());
                        }

                        foreach (explode(',', $row[$header['ip']]) as $ip) {
                            $tgt->interfaces[$ip] = new interfaces(null, null, null, $ip, null, $row[$header['hostname']], (isset($header['fqdn']) ? $row[$header['fqdn']] : null), null);
                        }

                        if (!empty($row[$header['category']])) {
                            $ste_cat = $db->get_STE_Cat_List($ste_id, $row[$header['category']]);
                            if (is_array($ste_cat) && count($ste_cat) && isset($ste_cat[0]) && is_a($ste_cat[0], 'ste_cat')) {
                                $tgt->set_Cat_ID($ste_cat[0]->get_ID());
                            }
                            else {
                                $ste_cat = new ste_cat(null, $ste_id, $row[$header['category']], null);
                                $ste_cat->set_ID($db->save_Category($ste_cat));

                                $tgt->set_Cat_ID($ste_cat->get_ID());
                            }
                        }

                        $db->save_Target($tgt);
                    }
                }
            }
            fclose($fh);
            unlink(TMP . "/$file");
        }
    }
}

if ($ste_id) {
    $cats = $db->get_STE_Cat_List($ste_id);
}

include_once 'header.inc';
?>

<script src="ste_script.min.js" type="text/javascript"></script>
<link href='/style/style.css' rel='stylesheet' type='text/css' />

<script type="text/javascript">
    var sel_tgts = [];
    function open_echecklist(id) {
      $('#echecklist').attr('src', 'echecklist_iframe.php?ste=<?php print (isset($ste_id) ? $ste_id : 0); ?>&cat=' + id);
      $('#echecklist').animate({'opacity': '1.00'}, 300, 'linear');
      $('#echecklist').css('display', 'block');
      view_box();
    }

    function toggle_hostname_ip() {
      $('.host').toggle();
      $('.ip').toggle();

      if ($('#toggle_host_ip').val() == 'Show IP')
        $('#toggle_host_ip').val("Show Name");
      else
        $('#toggle_host_ip').val("Show IP");
    }

    function delete_host() {
      if (!confirm("Are you sure you want to delete the selected target(s)")) {
        return;
      }

      $.ajax('/ajax.php', {
        data: {
          action: 'delete-host',
          selected_tgts: JSON.stringify(sel_tgts)
        },
        success: function (data) {
          if (data.error) {
            alert(data.error);
          }
          else if (data.success) {
            $('.tgt-sel:checked').parent().parent().slideUp(500);
            $('.tgt-sel:checked').parent().parent().remove();
          }
        },
        error: function (xhr, status, error) {
          console.error(error);
        },
        method: 'post',
        dataType: 'json'
      });
    }

    $(function () {
      $('.button,.button-delete').on('mouseover', function () {
        $(this).addClass('mouseover');
      });
      $('.button,.button-delete').on('mouseout', function () {
        $(this).removeClass('mouseover');
      });

      $('.expand').click(collapse_expand);
    });
</script>

<style type="text/css">
    .ip {
        display: none;
    }
    .header {
        display: inline-table;
        width: auto;
        background-color: #31363C;
        color: #fff;
    }
    .left_cat_header span {
        text-align: center;
        min-width: 25px;
        display: inline-block;
        padding: 0 3px;
    }
    .right_cat_header {
        width: 200px;
        float: right;
    }
    .cat_icons {
        background-size: 20px 20px;
        vertical-align: middle;
        width: 20px;
        height: 20px;
        padding-right: 2px;
    }
    .task-nr,.task-na,.task-np,.task-comp,.task-ip {
        text-align: center;
        width: 62px;
    }
    .checklist_image {
        width: 32px;
        vertical-align: middle;
    }
    .notes {
        width: 100%;
    }
    .table-header {
        width: 1200px;
        text-align: center;
        margin: auto;
    }
    #mentions {
        font-family: verdana, arial, sans-serif;
        position: absolute;
        bottom : 200px;
        left : 10px;
        color: #000;
        background-color: #ddd;
    }
    #mentions a {
        text-decoration: none;
        color: #222;
    }
    #mentions a:hover{
        text-decoration: underline;
    }
    #waiting {
        position: absolute;
        top: 0px;
        left: 0px;
        width: 100%;
        height: 100%;
        background: #000;
        opacity: 0.0;
        filter: alpha(opacity=0);
        z-index: 1000;
        display: none;
    }
    #loading {
        display: none;
    }
</style>

<div id='wrapper'>
    <div id='main-wrapper'>
        <div class='12u' id='main-content'>
            <div class="5grid-layout" style="text-align: right;overflow-y:auto;overflow-x:hidden;">
                <div class="row">
                    <div class="12u">
                        <div style='float: left; margin-top: 6px;'>
                            <form method="post" action="#">
                                ST&amp;E Name:
                                <select name='ste' style='width: 400px;' id="ste"
                                        onchange="setCookie('ste', this.value);
                                              this.form.submit();">
                                    <option value='0'> -- Please Select an ST&amp;E -- </option>
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

                        <div style='float: right;'>
                            <input type='button' class='button' id='toggle_host_ip' value='Show IP'
                                   onclick="javascript:toggle_hostname_ip();" />
                            <input type='button' class='button' value='Move To...'
                                   onclick="javascript:open_move_to();" />
                            <input type='button' class='button' value='Add Category'
                                   onclick="javascript:add_cat();" />
                            <input type='button' class='button' value='Add Host List'
                                   onclick="javascript:upload_host_list();" />
                            <input type='button' class='button-delete'
                                   onclick="javascript:delete_host();" value='Delete Host' />
                        </div>
                    </div>
                </div>
                <div id="container">
                    <div class="table-header">
                        <span class="header" style="width:100px;">Name</span>
                        <span class="header" style="width:100px;">OS</span>
                        <span class="header" style="width:100px;">Location</span>
                        <span class="header" style="width:60px;">
                            <form method="post" action="#" style="display:inline-block;">
                                <input type='hidden' name='action' value='update_auto' />
                                <input type='hidden' name='selected_tgts' id='auto_selected_tgts' />
                                <input type='hidden' name='ste'	value='<?php print isset($ste_id) ? $ste_id : ''; ?>' />
                                <select name='new_status' style='width: 60px;'
                                        onchange="$('#auto_selected_tgts').val(JSON.stringify(sel_tgts));
                                              if (update_Status(this))
                                                this.form.submit();">
                                    <option value='0'>Auto</option>
                                    <?php
                                    foreach ($task_status as $key => $val): print "<option value='$key'>$val</option>";
                                    endforeach;

                                    ?>
                                </select>
                            </form>
                        </span>
                        <span class="header" style="width:60px;">
                            <form method="post" action="#" style="display:inline-block;">
                                <input type='hidden' name='action' value='update_manual' />
                                <input type='hidden' name='selected_tgts' id='man_selected_tgts' />
                                <input type='hidden' name='ste'value='<?php print (isset($ste_id) ? $ste_id : ''); ?>' />
                                <select name='new_status' style='width: 60px;'
                                        onchange="$('#man_selected_tgts').val(JSON.stringify(sel_tgts));
                                              if (update_Status(this))
                                                this.form.submit();">
                                    <option value='0'>Man</option>
                                    <?php
                                    foreach ($task_status as $key => $val): print "<option value='$key'>$val</option>";
                                    endforeach;

                                    ?>
                                </select>
                            </form>
                        </span>
                        <span class="header" style="width:60px;">
                            <form method="post" action="#" style="display:inline-block;">
                                <input type='hidden' name='action' value='update_data' />
                                <input type='hidden' name='selected_tgts' id='data_selected_tgts' />
                                <input type='hidden' name='ste' value='<?php print (isset($ste_id) ? $ste_id : ''); ?>' />
                                <select name='new_status' style='width: 60px;'
                                        onchange="$('#data_selected_tgts').val(JSON.stringify(sel_tgts));
                                              if (update_Status(this))
                                                this.form.submit();">
                                    <option value='0'>Data</option>
                                    <?php
                                    foreach ($task_status as $key => $val): print "<option value='$key'>$val</option>";
                                    endforeach;

                                    ?>
                                </select>
                            </form>
                        </span>
                        <span class="header" style="width:60px;">
                            <form method="post" action="#" style="display:inline-block;">
                                <input type='hidden' name='action' value='update_fp_cat1' />
                                <input type='hidden' name='selected_tgts' id='review_selected_tgts' />
                                <input type='hidden' name='ste' value='<?php print (isset($ste_id) ? $ste_id : ''); ?>' />
                                <select name='new_status' style='width: 60px;'
                                        onchange="$('#review_selected_tgts').val(JSON.stringify(sel_tgts));
                                              if (update_Status(this))
                                                this.form.submit();">
                                    <option value='0'>FP/CAT I</option>
                                    <?php
                                    foreach ($task_status as $key => $val): print "<option value='$key'>$val</option>";
                                    endforeach;

                                    ?>
                                </select>
                            </form>
                        </span>
                        <span class="header" style="width:145px;">Scans</span>
                        <span class='header' style="width:145px;">Checklists</span>
                        <span class='header' style='width:344px;'>Notes</span>
                    </div>
                </div>
                <?php
                // print category headers
                if ($ste_id) {
                    $tgts = $db->get_Unassigned_Targets($ste_id);
                    $odd  = true;
                    if (is_array($tgts) && count($tgts)) {
                        $cat = new ste_cat(0, $ste_id, "Unassigned", null);
                        print $cat->get_Table_Row(count($tgts));

                        foreach ($tgts as $key => $tgt) {
                            $tgt->get_Table_Row($odd);
                            $odd = !$odd;
                        }
                    }

                    /**
                     * @var ste_cat $cat
                     */
                    foreach ($cats as $cat) {
                        print $cat->get_Table_Row();
                    }
                }
                else {
                    print "<div style='text-align:center;font-size:18pt;'>No ST&amp;E selected</div>";
                }

                ?>
            </div>
        </div>
    </div>
</div>
<input type="hidden" id="ops-page" value="main" />

<div id='tgt-notes' class="box">
    <input type='hidden' id='tgt-id' />
    <textarea id='notes' style='width:100%;height:75%;'></textarea>
    <input type='button' id='save-tgt-notes' value='Save' />
</div>

<div class="backdrop"></div>
<div id="move_to" class="box">
    <form method="post" action="#">
        <input type='hidden' name='selected_tgts' id='move_selected_tgts' />
        <input type='hidden' name='action' value='move_to' />
        <input type='hidden' name='ste' id='move_ste' value='<?php print (isset($ste_id) ? $ste_id : ''); ?>' />
        Move to category:
        <select name='move_to_cat' onchange="$('#move_selected_tgts').val(JSON.stringify(sel_tgts));
              this.form.submit();">
            <option value=''>-- Select Category --</option>
            <?php
            if (is_array($cats) && count($cats)) {
                foreach ($cats as $cat) {
                    print "<option value='{$cat->get_ID()}'>{$cat->get_Name()}</option>";
                }
            }

            ?>
        </select>
    </form>
</div>

<div id="edit_cat" class="box">
    <form method="post" action="#">
        <input type="hidden" name="selected_cat" id="selected_cat" />
        <input type="hidden" name="action" value="save_cat" />
        New Name: <input type="text" name="new_cat_name" id="new_cat_name" /><br />
        Analyst: <input type='text' name='analyst' id='analyst' /><br />
        <select name='scan_sources[]' id="scan_sources" multiple size='8'>
            <?php
            if (is_array($scan_srcs) && count($scan_srcs)) {
                foreach ($scan_srcs as $src) {
                    print "<option id='src_{$src->get_ID()}' value='{$src->get_ID()}'>{$src->get_Name()}</option>";
                }
            }

            ?>
        </select><br />
        <input type="submit" name="submit" value="Update Category" />
    </form>
</div>

<div id="add_cat" class="box">
    <form method="post" action="#">
        <input type='hidden' name='action' value='add_cat' />
        <input type='hidden' name='ste' id='add_ste' value='' />
        Category Name: <input type='text' name='new_cat' value='' /><br />
        <select name='scan_sources[]' multiple size='8'>
            <?php
            if (is_array($scan_srcs) && count($scan_srcs)) {
                foreach ($scan_srcs as $src) {
                    print "<option value='{$src->get_ID()}'>{$src->get_Name()}</option>";
                }
            }

            ?>
        </select><br />
        <input type='submit' name='submit' value='Add Category' />
    </form>
</div>

<div id="import_host_list" class="box">
    <script type="text/javascript" src="/script/dropzone/dropzone.min.js"></script>
    <link type="text/css" href="/script/dropzone/dropzone.min.css" rel="stylesheet" />
    <link type="text/css" href="/script/dropzone/basic.min.css" rel="stylesheet" />

    <script type="text/javascript">
            Dropzone.options.dropzone = {
              maxFilesize: 10,
              success: function (file, res) {
              },
              error: function (xhr, status, error) {
                console.error(xhr);
                console.error(error);
              },
              acceptedFiles: ".csv"
            };
            Dropzone.prototype.submitRequest = function (xhr, formData, files) {
              $('#host-list-file').val(files[0].name);
              var dt = new Date(files[0].lastModifiedDate);
              xhr.setRequestHeader('X-FILENAME', files[0].name);
              xhr.setRequestHeader('X-FILEMTIME', dt.toISOString());
              return xhr.send(formData);
            };
            Dropzone.autoDiscover = false;

            $(function () {
              var mydz = new Dropzone('#dropzone');
            });
    </script>

    <form class="dropzone" action="/upload.php" id="dropzone">
        <div class="fallback">
            <input type="file" name="file" multiple />
        </div>
    </form>

    <form method='post' action='#' style='margin-left: 20px;'
          onsubmit="$('#submit').attr('disabled', true);
                return true;">
        <input type='hidden' name='file' id='host-list-file' style='display:none;' />
        <input type='hidden' name='action' value='import_host_list' />
        <input type='hidden' name='ste' value='<?php print ($ste_id ? $ste_id : ''); ?>' />
        <input type='submit' name='submit' id='submit' value='Import Host List' />
    </form>
</div>

<div id="add_import" class="box">
    <div style='margin-left: 20px;'>
        <input type='text' id='location' placeholder='Physical Location...' /><br />
        <input type='button' id='add-scan' value='Add Scan Result' onclick='add_scans();' /><br />
        <label for='ignore_hidden' id='ignore_label'>Ignore Hidden Tabs in Excel eChecklists</label>
        <input type='checkbox' name='ignore_hidden' id='ignore_hidden' value='1' checked />
    </div>
</div>

<iframe id='echecklist' class='box' style='width: 80%; height: 80%; top: 10%; left: 10%;'> </iframe>

<div id="waiting"></div>
<div id="loading"></div>

<?php
include_once 'footer.inc';
