<?php
/**
 * File: stemgmt.inc
 * Author: Ryan Prather
 * Purpose: For adding or editing ST&Es
 * Created: Oct 21, 2014
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
 *  - Oct 21, 2014 - File created
 *  - Sep 1, 2016 - Copyright updated and updated file purpose
 *  - Apr 5, 2017 - Formatting
 *  - May 19, 2017 - Migrated to filtering and changed save button to match buttons throughout
 *  - Jun 3, 2017 - Fixed bug #230 and changed table stripping to be consistent across the system
 *  - Jan 20, 2018 - Removed CKEditor fields
 */
$page   = filter_input(INPUT_GET, 'p', FILTER_SANITIZE_STRING);
$ste_id = filter_input(INPUT_POST, 'ste', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
if (!$ste_id) {
    $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
}

$stes = $db->get_STE();

?>

<script type="text/javascript" src="/script/datatables/DataTables-1.10.9/js/jquery.dataTables.min.js"></script>

<link rel="stylesheet" type="text/css" href="/script/jQueryUI/css/ui-lightness/jquery-ui-1.10.3.custom.min.css" />
<link type='text/css' rel='stylesheet' href="/script/datatables/DataTables-1.10.9/css/jquery.dataTables.min.css" />

<?php
if ($page == 'STEMgmt') {

    ?>

    <form method='post' action='?p=EditSTE'>
        Select ST&amp;E:<br />
        <select name='ste' onchange="this.form.submit();">
            <option value='0'> -- Select ST&amp;E -- </option>
            <option value='new'>New...</option>
            <?php
            if (is_array($stes) && count($stes)) {
                foreach ($stes as $ste) {
                    print "<option value='{$ste->get_ID()}'>" .
                        "{$ste->get_System()->get_Name()}, {$ste->get_Site()->get_Name()}, {$ste->get_Eval_Start_Date()->format("M j, Y")}" .
                        "</option>";
                }
            }

            ?>
        </select>
    </form>

    <?php
}
elseif ($page == 'EditSTE' && is_numeric($ste_id) && $ste_id > 0) {
    $ste = $db->get_STE($ste_id);

    if (is_array($ste) && count($ste) && isset($ste[0]) && is_a($ste[0], 'ste')) {
        $ste = $ste[0];
    }
    else {
        die("Couldn't find the selected ST&amp;E");
    }

    ?>

    <style type='text/css'>
        #cke_scope, #cke_assumptions, #cke_constraints {
            display:none;
        }
    </style>

    <script type='text/javascript'>
        $(function () {
          $('#start_date').datepicker({
            dateFormat: "yy-mm-dd",
            minDate: 0,
            onSelect: function (date) {
              var dt2 = $('#end_date');
              var startDate = $(this).datepicker('getDate');
              var minDate = $(this).datepicker('getDate');
              startDate.setDate(startDate.getDate() + 30);
              //sets dt2 maxDate to the last day of 30 days window
              dt2.datepicker('option', 'maxDate', startDate);
              dt2.datepicker('option', 'minDate', minDate);
              //$(this).datepicker('option', 'minDate', minDate);
            }
          });
          $('#end_date').datepicker({dateFormat: "yy-mm-dd"});

          $('#host_table').DataTable({
            'stripeClasses': ['odd_row', 'even_row']
          });
    <?php /*
      CKEDITOR.replace('scope', {height: '100px', width: '675px', toolbar: [
      {name: 'document', items: ['Source']},
      {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
      {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
      {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
      ]});
      CKEDITOR.replace('assumptions', {height: '100px', width: '675px', toolbar: [
      {name: 'document', items: ['Source']},
      {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
      {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
      {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
      ]});
      CKEDITOR.replace('constraints', {height: '100px', width: '675px', toolbar: [
      {name: 'document', items: ['Source']},
      {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
      {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
      {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
      ]});
     */ ?>
        });

        function validate_Edit_STE() {
          if ($('#action') == 'Delete STE') {
            return confirm("Are you sure you want to delete this ST&E");
          }

          var ret = true;

          if ($('#start_date').val() > $('#end_date').val()) {
            alert("Your start date can't after the end date");
            ret = false;
          }

          if (!$('#start_date').val()) {
            alert("You must select a start date for this ST&E");
            ret = false;
          }

          if (!$('#end_date').val()) {
            alert("You must select an end date for this ST&E");
            ret = false;
          }

          if ($('#system').val() == "0") {
            alert("You must select a system for this ST&E");
            ret = false;
          }

          if ($('#site').val() == "0") {
            alert("You must select a site where this ST&E will be performed");
            ret = false;
          }

          return ret;
        }

        function show_subsystems() {
          if ($('#system').val() == '0') {
            alert('Select a primary system');
            $('#system').focus();
            return;
          }

          if ($('#add_subsystems').is(':checked'))
            $('#subsystem_container').show();
          else
            $('#subsystem_container').hide();

          $('#subsystems option').each(function () {
            if ($(this).val() == $('#system').val()) {
              $(this).remove();
              return;
            }
          });
        }
    </script>

    <form method='post' action='?p=EditSTE'>
        ST&amp;E:<br />
        <select name='ste' onchange="this.form.submit();">
            <option value='0'> -- Select ST&amp;E -- </option>
            <option value='new'>New...</option>
            <?php
            if (is_array($stes) && count($stes)) {
                foreach ($stes as $s) {
                    print "<option value='{$s->get_ID()}'" . ($ste_id == $s->get_ID() ? " selected" : "") . ">" .
                        "{$s->get_System()->get_Name()}, {$s->get_Site()->get_Name()}, {$s->get_Eval_Start_Date()->format("M j, Y")}" .
                        "</option>";
                }
            }

            ?>
        </select>
    </form>

    <form method='post' action='?p=STEMgmt' onsubmit="return validate_Edit_STE();">
        <div style='width:30%;float:left;'>
            <input type='hidden' name='ste' value='<?php print $ste_id; ?>' />
            <input type='hidden' name='action' value='save-ste' />
            Eval Start Date:
            <input type='text' name='start_date' id='start_date' value='<?php print $ste->get_Eval_Start_Date()->format('Y-m-d'); ?>' /><br />
            Eval End Date:
            <input type='text' name='end_date' id='end_date' value='<?php print $ste->get_Eval_End_Date()->format('Y-m-d'); ?>' /><br />
            <?php print "<script>console.log('" . json_encode($ste->get_System()) . "');</script>"; ?>
            System: <select name='system' id='system'>
                <?php
                foreach ($all_systems as $key => $sys) :
                    $selected = $ste->get_System()->get_ID() == $sys->get_ID() ? true : false;
                    print $sys->get_Option($selected);
                endforeach;

                ?>
            </select><br />
            <label for='add_subsystems'>Subsystems:</label>
            <input type='checkbox' name='add_subsystems' id='add_subsystems' value='1' onclick='javascript:show_subsystems();' <?php print $ste->is_Multiple() ? 'checked' : ''; ?> /><br />
            <div id='subsystem_container' <?php print $ste->is_Multiple() ? '' : "style='display: none;'"; ?>>
                <select name='subsystems[]' id='subsystems' multiple size='5' style='width:150px;'>
                    <?php
                    $substes = $db->get_Subsystems($ste);
                    $sub_sys = [];
                    $subs    = [];

                    foreach ($substes as $key => $sub_ste) :
                        $sub_sys[]                              = $sub_ste->get_System()->get_ID();
                        $subs[$sub_ste->get_System()->get_ID()] = $sub_ste->get_ID();
                    endforeach;

                    $all_stes = $db->get_STE();

                    foreach ($all_stes as $key => $current) {
                        $subs[$current->get_System()->get_ID()] = $current->get_ID();
                    }

                    foreach ($all_systems as $key => $sys) :
                        $selected = in_array($sys->get_ID(), $sub_sys) ? true : false;
                        $my_ste   = (isset($subs[$sys->get_ID()]) ? $subs[$sys->get_ID()] : $ste->get_ID());
                        print $ste->get_System()->get_ID() != $sys->get_ID() ? $sys->get_Option($selected, $my_ste) : '';
                    endforeach;

                    ?>
                </select>
                <br />
            </div>
            Site: <select name='site' id='site'>
                <?php
                foreach ($all_sites as $key => $s) :
                    $selected = $ste->get_Site()->get_ID() == $s->get_Id() ? true : false;
                    print $s->get_Option($selected);
                endforeach;

                ?>
            </select><br />
            Approving Official: <input type='text' name='ao' title='The office or individual that is going to approve or disapprove the system' value='<?php print $ste->get_AO(); ?>' /><br />
            <input type='button' class='button' name='action' value='Save STE' onclick='this.form.submit();' />
        </div>
        <div style='width:70%;float:left;'>
            <input type='hidden' name='scope' id='scope' value='' />
            <input type='hidden' name='assumptions' id='assumptions' value='' />
            <input type='hidden' name='constraints' id='constraints' value='' />
            <?php /*
            <label for="s">Scope:</label> <input type='checkbox' id='s' onclick="$('#cke_scope').toggle();" /><br />
            <textarea name='scope' id='scope' rows='5' cols='80'><?php print $ste->get_Scope(); ?></textarea><br />
            <label for="a">Assumptions:</label><input type='checkbox' id='a' onclick="$('#cke_assumptions').toggle();" /><br />
            <textarea name='assumptions' id='assumptions' rows='5' cols='80'><?php print $ste->get_Assumptions(); ?></textarea><br />
            <label for="cd">Constraints &amp; Dependencies:</label><input type='checkbox' id='cd' onclick="$('#cke_constraints').toggle();" /><br />
            <textarea name='constraints' id='constraints' rows='5' cols='80'><?php print $ste->get_Constraints(); ?></textarea>
             */ ?>
        </div>
    </form>
    <form method='post' action='ste_export_import.php' style='display:inline;'>
        <input type='hidden' name='ste' value='<?php print $ste_id; ?>' />
        <input type='submit' name='export' value='Export STE' />
        <?php
        $tgts = $db->get_Target_Details($ste_id);
        if (is_array($tgts) && count($tgts)) {

            ?>
            <input type='submit' name='export' value='Export Host List' />
        <?php } ?>
    </form>

    <form method='post' action='compare.php' style='display:inline;'>
        <input type='hidden' name='left_ste' value='<?php print $ste_id; ?>' />
        <select name='right_ste'>
            <option value='0'> -- Select ST&amp;E -- </option>
            <?php
            if (is_array($stes) && count($stes)) {
                foreach ($stes as $ste) {
                    print "<option value='{$ste->get_ID()}'>" .
                        "{$ste->get_System()->get_Name()}, {$ste->get_Site()->get_Name()}, {$ste->get_Eval_Start_Date()->format("M j, Y")}" .
                        "</option>";
                }
            }

            ?>
        </select>
        <input type='submit' name='compare' value='Compare ST&E' />
    </form>

    <table id='host_table' class='display'>
        <thead>
            <tr>
                <th style='width:50px;'>ID</th>
                <th style='width:200px;'>Hostname</th>
                <th style='width:150px;'>IPv4</th>
                <th style='width:250px;'>FQDN</th>
                <th style='width:200px;'>Operating System</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $odd = true;
            if (is_array($tgts) && count($tgts) && isset($tgts['id'])) {
                $tgts = array(0 => $tgts);
            }
            if (is_array($tgts) && count($tgts) && isset($tgts[0]) && is_a($tgts[0], 'target')) {
                foreach ($tgts as $key => $tgt) {
                    $interfaces = '';
                    $fqdn       = '';
                    $odd        = !$odd;

                    $os = $db->get_Software($tgt->get_OS_ID())[0];

                    foreach ($tgt->interfaces as $key2 => $int) {
                        $interfaces .= $int->get_IPv4() . ", ";
                        $fqdn       .= $int->get_FQDN() . ", ";
                    }

                    print "<tr>" . // class='".($odd ? 'odd' : 'even')."'>".
                        "<td>{$tgt->get_ID()}</td>" .
                        "<td>{$tgt->get_Name()}</td>" .
                        "<td>" . substr($interfaces, 0, -2) . "</td>" .
                        "<td>" . substr($fqdn, 0, -2) . "</td>" .
                        "<td>{$tgt->get_OS_String()}</td>" .
                        "</tr>";
                }
            }

            ?>
        </tbody>
    </table>

    <?php
}
elseif ($page == 'EditSTE' && $ste_id == 'new') {

    ?>

    <style type='text/css'>
        #cke_scope, #cke_assumptions, #cke_constraints {
            display:none;
        }
    </style>

    <script type='text/javascript'>
        $(function () {
          $('#start_date').datepicker({
            dateFormat: "yy-mm-dd",
            minDate: -30,
            onSelect: function (date) {
              var dt2 = $('#end_date');
              var startDate = $(this).datepicker('getDate');
              var minDate = $(this).datepicker('getDate');
              startDate.setDate(startDate.getDate() + 30);
              //sets dt2 maxDate to the last day of 30 days window
              dt2.datepicker('option', 'maxDate', startDate);
              dt2.datepicker('option', 'minDate', minDate);
              //$(this).datepicker('option', 'minDate', minDate);
            }
          });
          $('#end_date').datepicker({dateFormat: "yy-mm-dd"});
    <?php /*
      CKEDITOR.replace('scope', {height: '100px', width: '675px', toolbar: [
      {name: 'document', items: ['Source']},
      {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
      {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
      {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
      ]});
      CKEDITOR.replace('assumptions', {height: '100px', width: '675px', toolbar: [
      {name: 'document', items: ['Source']},
      {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
      {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
      {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
      ]});
      CKEDITOR.replace('constraints', {height: '100px', width: '675px', toolbar: [
      {name: 'document', items: ['Source']},
      {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
      {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
      {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
      ]});
     */ ?>
        });

        function validate_Add_STE() {
          var ret = true;

          if ($('#start_date').val() > $('#end_date').val()) {
            alert("Your start date can't be after the end date");
            ret = false;
          }

          if (!$('#start_date').val()) {
            alert("You must select a start date for this ST&E");
            ret = false;
          }

          if (!$('#end_date').val()) {
            alert("You must select an end date for this ST&E");
            ret = false;
          }

          if ($('#system').val() == "0") {
            alert("You must select a system for this ST&E");
            ret = false;
          }

          if ($('#site').val() == "0") {
            alert("You must select a site where this ST&E will be performed");
            ret = false;
          }


          if (ret) {
            $('#action').prop("disabled", true);
          }
          return ret;
        }

        function show_subsystems() {
          if ($('#system').val() == '0') {
            alert('Select a primary system');
            $('#system').focus();
            return;
          }

          if ($('#add_subsystems').is(':checked'))
            $('#subsystem_container').show();
          else
            $('#subsystem_container').hide();

          $('#subsystems option').each(function () {
            if ($(this).val() == $('#system').val()) {
              $(this).remove();
              return;
            }
          });
        }
    </script>

    <form method='post' action='?p=STEMgmt' onsubmit="return validate_Add_STE();">
        <input type='hidden' name='action' value='save-ste' />
        <div style='width:30%;float:left;'>
            Eval Start Date:
            <input type='text' name='start_date' id='start_date' /><br />
            Eval End Date:
            <input type='text' name='end_date' id='end_date' /><br />
            System:
            <select name='system' id='system'>
                <option value='0'>-- Please Select A System --</option>
                <?php
                foreach ($all_systems as $key => $sys):print $sys->get_Option();
                endforeach;

                ?>
            </select><br />
            <label for='add_subsystems'>Subsystems:</label>
            <input type='checkbox' name='add_subsystems' id='add_subsystems' value='1' onclick='javascript:show_subsystems();' /><br />
            <div id='subsystem_container' style='display:none;'>
                <select name='subsystems[]' id='subsystems' multiple size='5' style='width:150px;'>
                    <?php
                    foreach ($all_systems as $key => $sys):print $sys->get_Option();
                    endforeach;

                    ?>
                </select><br />
            </div>
            Site:
            <select name='site' id='site'>
                <option value='0'>-- Please Select A Site --</option>
                <?php
                foreach ($all_sites as $key => $s):print $s->get_Option();
                endforeach;

                ?>
            </select><br />
            Approving Official: <input type='text' name='ao' title='The office or individual that will approve or disapprove the system' /><br />
            <input type='button' class='button' id='action' value='Save STE' onclick='this.form.submit();' />
        </div>
        <div style='width:70%;float:left;'>
            <input type='hidden' name='scope' id='scope' value='' />
            <input type='hidden' name='assumptions' id='assumptions' value='' />
            <input type='hidden' name='constraints' id='constraints' value='' />
            <?php /*
              <label for="s">Scope:</label> <input type='checkbox' id='s' onclick="$('#cke_scope').toggle();" /><br />
              <textarea name='scope' id='scope' rows='5' cols='80'>
              [describe the scope of the testing, including systems tested and excluded (and reason for exclusions)]
              </textarea><br />
              <label for="a">Assumptions:</label><input type='checkbox' id='a' onclick="$('#cke_assumptions').toggle();" /><br />
              <textarea name='assumptions' id='assumptions' rows='5' cols='80'>
              (<span style="color:green;">U</span>) The following assumptions were made during planning and execution of the ST&amp;E:
              <ul style="list-style-type:disc;">
              <li>(<span style="color:green;">FOUO</span>) Adequate access to the system and required personnel will be provided prior to conduct of ST&amp;E to support development and dry run testing of the ST&amp;E procedures.</li>
              <li>(<span style="color:green;">FOUO</span>) The system will be up and fully operational in the specified configuration at the time of testing.</li>
              <li>(<span style="color:green;">FOUO</span>) All required personnel will be available for the duration of the ST&amp;E.</li>
              <li>(<span style="color:green;">FOUO</span>) [insert other assumptions as necessary]</li>
              </ul>
              </textarea><br />
              <label for="cd">Constraints &amp; Dependencies:</label><input type='checkbox' id='cd' onclick="$('#cke_constraints').toggle();" /><br />
              <textarea name='constraints' id='constraints' rows='5' cols='80'>
              (<span style="color:green;">U</span>) The following potential constraints and dependencies were encountered that could affect the accuracy and completeness of the results.
              <ul style="list-style-type:disc;">
              <li>(<span style="color:green;">FOUO</span>) The accuracy and completeness of the ST&amp;E results is dependent on the accuracy and completeness of the information provided to the ST&amp;E team before and during the testing.</li>
              <li>(<span style="color:green;">FOUO</span>) [insert other issues encountered during testing]</li>
              </ul>
              (<span style="color:green;">U</span>) These constraints and dependencies had minimal impact on providing complete and accurate results.
              </textarea>
             */ ?>
        </div>
    </form>

    <?php
}
