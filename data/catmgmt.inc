<?php
/**
 * File: catmgmt.inc
 * Author: Ryan Prather
 * Purpose: For handling the catalog management page
 * Created: May 2, 2018
 *
 * Portions Copyright 2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 * - May 2, 2018 - File created, Moved catalog mgmt html content from index page to this for easier viewing and refined the code a little
 */

?>

<script src='/script/datatables/DataTables-1.10.9/js/jquery.dataTables.min.js'></script>
<link rel="stylesheet" href="/script/datatables/DataTables-1.10.9/css/jquery.dataTables.min.css" />
<link rel='stylesheet' href='/script/jquery-ui/jquery-ui.min.css' />

<style type='text/css'>
    #availableSoftware {
        height: 227px;
        width: 240px;
        overflow-x: scroll;
        font-size: 14px;
        line-height: 1.25em;
    }

    .swmouseover {
        background-color: #1D57A0;
        color: #fff;
        cursor: pointer;
    }
</style>
<script src='data.min.js' type='text/javascript'></script>
<script type='text/javascript'>
    $(function () {
      $('#catalog').DataTable({
        'stripeClasses': ['odd_row', 'even_row']
      });
      $('.close, .backdrop').click(function () {
        close_box();
      });
      $('#release-date').datepicker();
      $('.button,.button-delete').mouseover(function(){$(this).addClass('mouseover');});
      $('.button,.button-delete').mouseout(function(){$(this).removeClass('mouseover');});
    });
</script>
<style type="text/css">
    thead {
        background-image: linear-gradient(to bottom, #ECECEC, rgba(177,177,177,0.72));
        color: #4c4c4c;
    }
</style>

<div>
    <table id='catalog' class='display'>
        <thead>
            <tr>
                <th>File Name</th>
                <th>Status</th>
                <th>Start Time</th>
                <th>% Complete</th>
                <th>STIG Count</th>
            </tr>
        </thead>

        <tbody>
            <?php
            $cat_scripts = $db->get_Catalog_Script();
            $odd         = true;
            foreach ($cat_scripts as $key => $cat_script) {
                print <<<EOL
<tr>
    <td onclick='javascript:get_cat_data("{$cat_script->file_name}");'><a href='javascript:void(0);'>{$cat_script->file_name}</a></td>
    <td>{$cat_script->status}</td>
    <td>{$cat_script->start_time->format("Y-m-d H:i:s")}</td>
    <td>{$cat_script->perc_comp}</td>
    <td>{$cat_script->stig_count}</td>
</tr>
EOL;
            }

            ?>
        </tbody>
    </table>
</div>

<div id='popup' class='box'>
    <div style='display:inline-block;width:49%;vertical-align:top;'>
        <input type='hidden' id='id' />
        Checklist ID: <span id='checklist-id'></span><br />
        Name: <input type='text' id='name' /><br />
        Description: <textarea id='description'></textarea><br />
        Version: <span id='version'></span><br />
        Release: <span id='release'></span><br />
        Release Date: <input type='text' id='release-date' /><br />
        Icon: <input type='text' id='icon' title='Put file in <?php print realpath(DOC_ROOT . "/img/checklist_icons") ?> and copy/paste the base filename here' /><br />
        Type: <span id='type'></span><br />
        <input type='button' class="button" value='Save' onclick='save_checklist();' />
        <!-- <input type='button' class='button-delete' value='Delete' onclick='' /> -->
    </div>

    <div style='display:inline-block;width:49%;'>
        <select id='software' multiple size='10' style='width:275px;' title='Double-click to remove software'></select><br />

        Add CPE: <input type='text' id='cpe' onkeyup='javascript:autocomplete_software();' />&nbsp;&nbsp;
        <label for='os'>OS?</label>
        <input type='checkbox' id='os' /><br />
        <div id="availableSoftware"></div>
    </div>
</div>

<div class="backdrop"></div>