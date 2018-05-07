<?php
/**
 * File: ops-top.inc
 * Author: Ryan
 * Purpose: Display the ST&E selection drop down and required buttons
 * Created: Sep 1, 2016
 *
 * Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 1, 2016 - File created
 *  - Jan 15, 2018 - Fixed wrong action on drop-down selection
 */
include_once 'database.inc';

if (!$db) {
    $db = new db();
}

if (!isset($ste_id)) {
    $ste_id = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    if (!$ste_id) {
        $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    }
}

$stes = $db->get_STE();

?>

<script type="text/javascript">
    $(function () {
        $('.button').mouseover(function () {
            $(this).addClass("mouseover");
        })
                .mouseout(function () {
                    $(this).removeClass('mouseover');
                });
    });
</script>

<div class="row">
    <div class="12u">
        <div style='float: left; margin-top: 6px;'>
            <form method="post" action="#">
                ST&amp;E Name:
                <select name='ste' style='width: 400px;' id="ste"
                        onchange="setCookie('ste', this.value);this.form.submit();">
                    <option value='0'> -- Please Select An ST&amp;E -- </option>
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
            <input type='button' class='button' id='toggle_host_ip'
               onclick="javascript:toggle_hostname_ip();" value='Show IP' />
            <input type='button' class='button' value='Move To...'
               onclick="javascript:open_move_to();" />
            <input type='button' class='button' value='Add Category'
               onclick="javascript:add_cat();" />
            <input type='button' class='button' value='Add Host List'
               onclick="javascript:upload_host_list();" />
            <input type='button' class='button-delete' value='Delete Host'
               onclick="javascript:delete_host();" />
        </div>
    </div>
</div>
