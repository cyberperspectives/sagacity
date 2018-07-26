<?php
/**
 * File: target-filter.inc
 * Author: Ryan
 * Purpose: This file contains all that is necessary for the display of the target filter.
 *    When filtering, the results go into a dive with the id='target-filter-results', place wherever desired.
 * Created: Aug 21, 2016
 *
 * Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Aug 21, 2016 - File created
 *  - Oct 10, 2016 - Converted AJAX code to retrieve JSON from request instead of XML (bug #5)
 *  - Jan 30, 2017 - Formatting
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 *  - Mar 13, 2017 - Added support for notice when no targets found or timeouts and increased timeout to 60 seconds
 */
include_once 'database.inc';

if (!$db) {
    $db = new db();
}

$filters = $db->get_Filters('target');
$col = 250;
$col2 = 398;

if (isset($target_filter_width)) {
    $target_filter_width -= 40;
    $col = floor($target_filter_width / 5);
    $col2 = $col * 2;
} else {
    $target_filter_width = 1200;
}

$stes = $db->get_STE_List();

if (!isset($ste_id) || !$ste_id) {
    $ste_id = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT);
    if (!$ste_id) {
        $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT);
    }
}

?>

<script src="/script/skinable_tabs.min.js" type='text/javascript'></script>

<script type='text/javascript'>
    var load_more = false;
    /**
     * save_target_filter function
     *    Function built to perform AJAX query of the database and save the filter to the database.
     */
    function save_target_filter() {
        if ($('#filter option').length < 1) {
            alert("Please add a filter to save");
            console.warn("No filters to save");
            return;
        } else if ($('#filter-name').val() === '') {
            alert("Please type a filter name");
            console.warn("No filter name");
            return;
        }
        var criteria = '';
        $('#filter option').each(function () {
            if ($(this).text())
                criteria += $(this).text() + "\n";
        });
        $.ajax('/ajax.php', {
            data: {
                'action': 'save_filter',
                'criteria': criteria,
                'type': 'target',
                'name': $('#filter-name').val()
            },
            success: save_filter_result,
            dataType: 'text',
            method: 'post'
        });
    }

    /**
     * save_filter_result
     *    This function is built to perform whatever actions are required on the returned AJAX data
     *
     * @param data
     *            The data returned from the AJAX query
     */
    function save_filter_result(data) {
        if (data === 'false') {
            alert('Filter saving failed');
        }
    }

    /**
     * add_filter function
     *    This function adds a selected filter and the data to the select box for querying
     */
    function add_filter() {
        if ($('#filter-options').val() === '0') {
            alert('Must select a filter option');
            console.error("No filter option selected");
            return;
        }

        var op = ' = ';
        var op_str = ' IS ';
        if ($('#not').is(':checked') && $('#like').is(':checked')) {
            op = ' !~ ';
            op_str = ' NOT LIKE ';
        } else if ($('#not').is(':checked')) {
            op = ' != ';
            op_str = ' NOT EQUAL ';
        } else if ($('#like').is(':checked')) {
            op = ' ~= ';
            op_str = ' LIKE ';
        }

        var filter = '';
        switch ($('#filter-options').val()) {
            case 'cat':
                filter = $('#cats').val();
                break;
            case 'auto_status':
            case 'man_status':
            case 'data_status':
            case 'fp_cat1_status':
                filter = $('#task-status').val();
                break;
            case 'os':
            case 'sw':
                filter = $('#sw-filter').val();
                break;
            default:
                filter = $('#filter-text').val();
        }

        $('#filter').append($('<option>', {
            text: $('#filter-options option:selected').text() +
                    op + '\'' + filter + '\'',
            title: $('#filter-options option:selected').text() +
                    op_str + '\'' + filter + '\''
        }));
        filter_clean_up();
    }

    /**
     * First check and see if there is a function already declared called collapse_expand_data
     *    If the function is not delcared in the document then declare and set it.
     */
    if (typeof window.collapse_expand_data === 'undefined') {
        window.collapse_expand_data = function (selection) {
            if ($('#' + selection + '-img').attr('src') === '/img/right-arrow.png') {
                $('#' + selection + '-img').attr('src', '/img/down-arrow.png');
            } else {
                $('#' + selection + '-img').attr('src', '/img/right-arrow.png');
            }

            $('#' + selection).toggle(300);
        };
    }

    /**
     * execut_filter function
     *    This function performs a AJAX query to execute the filter and retrieve the applicable data.
     */
    function execute_filter() {
        if ($('#filter option').length === 0) {
            alert('Please add something to filter');
            console.error('Nothing to filter');
            return;
        }
        if ($('#ste').val() === 0) {
            alert("Please select an ST&E");
            console.error("No ST&E selected");
            return;
        }
        var criteria = '';
        $('#filter option').each(function () {
            if ($(this).text())
                criteria += $(this).text() + "\n";
        });
        $.ajax('/ajax.php', {
            data: {
                action: 'target-filter',
                ste: $('#ste').val(),
                'criteria': criteria,
                start_count: $('#filter-start').val(),
                count: $('#filter-count').val()
            },
            success: display_target_filter_results,
            error: function (xhr, status, error) {
                if (status === 'timeout') {
                    alert("Request timed out");
                } else {
                    console.error(error);
                }
            },
            dataType: 'json',
            timeout: 60000,
            method: 'post'
        });
    }

    /**
     * display_target_filter_results function
     *    This function displays the data that was retrieved from the AJAX query (execute_filter)
     *
     * @param data
     *            Returned AJAX data
     */
    function display_target_filter_results(data) {
        if ($('#target-filter-results').length === 0) {
            console.error("Cannot find place to populate targets");
        }

        if (data.error) {
            alert(data.error);
            return;
        }

        if (data.count < 1) {
            $('#target-filter-results').html('No targets found');
            return;
        }

        var odd = true;
        if (!load_more) {
            $('#target-filter-results').html("");
        }

        if ($('#filter-count').val() !== 'all') {
            $('#filter-start').val(parseInt($('#filter-start').val()) + parseInt($('#filter-count').val()));
        } else {
            $('#filter-start').val(0);
        }

        for (var x in data.targets) {
            $('#target-filter-results').append(
                    "<div class='" + (odd ? "odd_row" : "even_row") + " cat_" + data.targets[x].cat_id + "' style='border:none;'>" +
                    "<span class='cat-cell' style='width:150px;text-align:left'>" +
                    "<input type='checkbox' value='" + data.targets[x].id + "' onclick='javascript:update_tgt_chk(this);' />" +
                    "<a href='target.php?ste=" + data.targets[x].ste_id + "&tgt=" + data.targets[x].id + "' class='host'>" + data.targets[x].name + "</a><br />" +
                    "<img src='/img/notes.png' style='width:24px;' onclick='get_notes(" + data.targets[x].id + "); ' />" +
                    "</span>" +
                    "<span class='cat-cell' style='width:150px;line-height:1.25em;'>" + data.targets[x].os + "</span>" +
                    "<span class='cat-cell' style='width:145px;'>" +
                    (data.targets[x].scans ? data.targets[x].scans : "&nbsp;") +
                    "</span>" +
                    "<span class='cat-cell' style='width:145px;'>" +
                    (data.targets[x].chk ? data.targets[x].chk : "&nbsp;") +
                    "</span>" +
                    "</div>"
                    );
            odd = !odd;
        }

        if ($('#filter-count').val() !== 'all') {
            if (data.count === $('#target-filter-results').find('div').length) {
                $('#load-more').hide();
            } else if (data.count > $('#filter-count').val()) {
                $('#load-more').show();
            }
        }

        load_more = false;
    }

    /**
     * retrieve_saved_filter function
     *    This function performs an AJAX query to retrieves the selected saved query from the database for display
     */
    function retrieve_saved_filter() {
        $('#filter-start').val(0);
        $('#filter option').remove();

        $.ajax('/ajax.php', {
            data: {
                action: 'get-saved-filter',
                'type': 'target',
                name: $('#saved-filter').val()
            },
            success: function (data) {
                for (var x in data) {
                    if (data[x]) {
                        $('#filter').append("<option>" + data[x] + "</option>");
                    }
                }

                execute_filter();
            },
            dataType: 'json',
            timeout: 1000,
            method: 'post'
        });
    }

    /**
     * change_filter_option function
     *    This function changes the display for specific filter types.
     */
    function change_filter_option() {
        $('.filter').hide();
        switch ($('#filter-options').val()) {
            case 'cat':
                $('#cats').show();
                break;
            case 'auto_status':
            case 'man_status':
            case 'data_status':
            case 'fp_cat1_status':
                $('#task-status').show();
                break;
            case 'os':
            case 'sw':
                $('#sw-filter').show();
                break;
            default:
                $('#filter-text').show();
        }
    }

    /**
     * filter_software function
     *    This function performs an AJAX query to retrive possible CPE matches from the typed filter (inc OS)
     */
    function filter_software() {
        var action = 'sw_filter';
        if ($('#filter-options').val() === 'os') {
            action = 'os_filter';
        }

        if ($('#sw-filter').val().length < 3) {
            return;
        }

        $.ajax('/ajax.php', {
            data: {
                'action': action,
                tgt_id: '<?php print isset($_REQUEST['tgt']) ? $_REQUEST['tgt'] : ''  ?>',
                filter: $('#sw-filter').val()
            },
            success: function (data) {
                $('#availableSoftware div').remove();

                for (var x in data) {
                    $('#availableSoftware').append("<div sw_id='" + data[x].sw_id + "' cpe='" + data[x].cpe + "'>" + data[x].sw_string + "</div>");
                }

                $('#availableSoftware div').each(function () {
                    $(this).on({
                        mouseover: function () {
                            $(this).addClass("swmouseover");
                        },
                        mouseout: function () {
                            $(this).removeClass("swmouseover");
                        },
                        click: function () {
                            if ($('#filter-options').val() === 'os') {
                                $('#filter').append("<option title=\"os IS '" + $(this).attr('cpe') + "'\">OS = '" + $(this).attr('cpe') + "'</option>");
                            } else {
                                $('#filter').append("<option title=\"sw IS '" + $(this).attr('cpe') + "'\">SW = '" + $(this).attr('cpe') + "'</option>");
                            }
                            $('#availableSoftware').children().remove();
                            $('#availableSoftware').hide();
                            $('#filter').show();
                            filter_clean_up();
                        }});
                });

                $('#availableSoftware').show();
                $('#filter').hide();
            },
            dataType: 'json',
            method: 'post',
            timeout: 10000
        });
    }

    /**
     * filter_clean_up function
     *    This function was built to clean up the filter and reset it.
     */
    function filter_clean_up() {
        $('#filter-start').val(0);
        $('#filter-options').val(0);
        $('#filter-text').val('');
        $('#sw-filter').val('');
        $('#like').attr('checked', false);
        $('#not').attr('checked', false);
        $('#sw-filter,#availableSoftware,.filter').hide();
        $('#filter-text,#filter').show();
    }

    /**
     * Function to get the notes for the target
     *
     * @param tgt_id
     */
    function get_notes(tgt_id) {
        $.ajax('/ajax.php', {
            data: {
                action: 'get-target-notes',
                'tgt-id': tgt_id
            },
            beforeSend: function () {
            },
            success: function (data) {
                $('#notes').html(data.notes);
            },
            error: function (xhr, status, error) {
                console.error(error);
            },
            complete: function () {
            },
            dataType: 'json',
            method: 'post',
            timeout: 1000
        });
    }
</script>

<style type='text/css'>
    .title {
        width: 1178px;
        background-color: #808080;
        font-size: 14pt;
        font-weight: bolder;
        font-style: italic;
        text-align: left;
        padding-left: 20px;
        color: black;
        margin-top: 5px;
        border: solid 1px black;
    }

    #load-more {
        width: 100%;
        text-align: center;
        background-color: #808080;
        display: none;
    }

    #load-more a {
        color: #fff;
        font-size: 18px;
        text-decoration: none;
    }

    .checklist_image {
        width: 32px;
        vertical-align: middle;
    }

    .col {
        width: <?php print $col - 10; ?>px;
        margin: 5px;
        height: 108px;
        display: inline-block;
        vertical-align: top;
    }

    .col2 {
        width: <?php print $col2 - 10; ?>px;
        margin: 5px;
        height: 108px;
        display: inline-block;
        vertical-align: top;
    }

    .swmouseover {
        background-color: #1D57A0;
        color: #fff;
        cursor: pointer;
    }

    .header {
        background-color: #31363C;
        color: #fff;
        display: table-cell;
    }

    .table-header {
        width: <?php print($target_filter_width += 22); ?>px;
        text-align: center;
    }

    .header-col {
        width: 49%;
        display: inline-block;
    }
</style>

<div class='title'>
    <div class='header-col'>
        <img id='cat-filter-img' src='/img/right-arrow.png' onclick="javascript:collapse_expand_data('cat-filter');" style='width: 20px;' />
        &nbsp;&nbsp;Target Filter...
        <select name='ste' id='ste'>
            <?php print $stes; ?>
        </select>
    </div>

    <div class='header-col'>
        <select name='saved-filter' id='saved-filter' onchange="retrieve_saved_filter();">
            <option value='0'>Saved Filters...</option>
            <?php
            foreach ($filters as $filter) {
                print "<option>" . $filter['name'] . "</option>";
            }

            ?>
        </select>
        <input type='text' name='filter-name' id='filter-name' />
        <input type='button' name='save-filter' value='Save Filter' onclick="javascript:save_target_filter();" />
    </div>
</div>

<div id='cat-filter' style='display: none;'>
    <input type='hidden' id='filter-start' value='0' />
    <div class='col'>
        <select id='filter-options' onchange="javascript:change_filter_option();" style='width:175px;'>
            <option value='0'>Filter options...</option>
            <option value='cat'>Category</option>
            <option value='name'>Name</option>
            <option value='os'>OS</option>
            <option value='sw'>Installed Software</option>
            <option value='auto_status'>Auto Status</option>
            <option value='man_status'>Manual Status</option>
            <option value='data_status'>Data Gathering Status</option>
            <option value='fp_cat1_status'>FP/Cat I Status</option>
            <option value='open_port' title='tcp/{port #} or udp/{port #}'>Open Port</option>
        </select><br />
        <select id='cats' class='filter' style='display: none;'>
            <?php
            if (isset($ste)) {
                $cats = $db->get_STE_Cat_List($ste);
                foreach ($cats as $cat) {
                    print "<option value='" . $cat->get_ID() . "'>" . $cat->get_Name() . "</option>";
                }
            }

            ?>
        </select>
        <select id='task-status' class='filter' style='display: none;'>
            <?php
            $task_status = $db->get_Task_Statuses();
            foreach ($task_status as $id => $status) {
                print "<option>$status</option>";
            }

            ?>
        </select>
        <input type='text' id='sw-filter' class='filter' placeholder='CPE...' style='display: none;' onkeyup="javascript:filter_software();" autocomplete="off" />
        <input type='text' class='filter' id='filter-text' placeholder='Filter...' /><br />

        <label for='not'>Not?</label>
        <input type='checkbox' id='not'	value='1' />
        <label for='like'>Like?</label>
        <input type='checkbox' id='like' value='1' />
        <input type='button' id='add' value='Add'	onclick="javascript:add_filter();" />
    </div>

    <div class='col2'>
        <div id='availableSoftware' class='filter-results' style='z-index: 1000; display: none; overflow-x: scroll; height: 110px;'></div>

        <select name='filter[]' id='filter' multiple size='4' style="width:<?php print $col2 - 15; ?>px;height:110px;" title="Double-click to remove filter" ondblclick="$('#filter-start').val(0); $('#filter option:selected').remove();">
        </select>
    </div>

    <div class='col' style='text-align: center;'>
        <select id='filter-count'>
            <option value='all'>All</option>
            <option value='5'>5</option>
            <option value='10'>10</option>
            <option value='25'>25</option>
            <option value='50'>50</option>
            <option value='100'>100</option>
        </select><br /> <input type='button' name='run-filter'
                               value='Filter...' onclick="javascript:execute_filter();" />
    </div>
</div>

<div id='target-header'>
    <div class='table-header' style='border: 0;'>
        <span class='header' style='width:<?php print ($target_filter_width * 0.125); ?>px;text-align:left'>Name</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.125); ?>px;line-height:1.25em;'>OS</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.12083); ?>px;'>Scans</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.12083); ?>px;'>Checklists</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>I</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>II</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>III</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>NF</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>NA</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>NR</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>C</span>
        <span class='header' style='width:<?php print ($target_filter_width * 0.05); ?>px;'>A</span>
    </div>
</div>
<div id='target-filter-results'></div>
<div id='load-more'>
    <a href='javascript:void(0);'
       onclick='load_more = true;execute_filter();'>Load More...</a>
</div>
