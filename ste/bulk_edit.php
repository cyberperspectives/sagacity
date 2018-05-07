<?php
/**
 * File: bulk_edit.php
 * Author: Ryan Prather
 * Purpose: Allow for multiple hosts in a category to be editted in specific ways
 * Created: May 14, 2014
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
 *  - May 14, 2014 - File created
 *  - Sep 1, 2016 - Copyright updated and functions for class merger
 * 					Converted ajax to php instead of cgi
 * 					Standardized other content
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 *  - Apr 5, 2017 - Formatting
 *  - Aug 28, 2017 - Fixed bugs #285 & #269, cleaned up code, & use filter_input method
 *  - Aug 31, 2017 - Fixed bug #269, #289, & #290
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$db = new db();

$int = array(
  'filter' => FILTER_VALIDATE_INT,
  'flag'   => FILTER_NULL_ON_FAILURE
);
$string = array(
  'filter' => FILTER_SANITIZE_STRING,
  'flag'   => FILTER_NULL_ON_FAILURE
);
$boolean = array(
  'filter' => FILTER_VALIDATE_BOOLEAN,
  'flag'   => FILTER_NULL_ON_FAILURE
);

$args = array(
  'action'          => $string,
  'cat'             => $int,
  'selected_tgts'   => $string,
  'osSoftware'      => $int,
  'location'        => $string,
  'auto_status'     => $int,
  'man_status'      => $int,
  'data_status'     => $int,
  'fp_cat1_status'  => $int,
  'remove_existing' => $boolean,
  'checklists'      => array(
    'filter' => FILTER_VALIDATE_INT,
    'flags'  => FILTER_REQUIRE_ARRAY
  ),
  'post_process'    => $boolean
);

$post = filter_input_array(INPUT_POST, $args);
$cat = filter_input(INPUT_GET, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$ste = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

$tgts = $db->get_Target_By_Category($cat);
$task_statuses = $db->get_Task_Statuses();
$task_statuses[null] = 'Not Reviewed';

if ($post['action'] == 'update_bulk') {
  set_time_limit(300);
  $sel_tgts = json_decode(html_entity_decode($post['selected_tgts']));

  foreach ($sel_tgts as $tgt_id) {
    $tgt = $db->get_Target_Details($ste, $tgt_id)[0];
    if ($post['cat']) {
      $tgt->set_Cat_ID($post['cat']);
    }

    if ($post['osSoftware']) {
      $os = $db->get_Software($post['osSoftware']);
      if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
        $tgt->set_OS_ID($os[0]->get_ID());
        $tgt->set_OS_String($os[0]->get_Shortened_SW_String());
      }
    }

    if ($post['location']) {
      $tgt->set_Location($post['location']);
    }

    if ($post['auto_status']) {
      $tgt->set_Auto_Status_ID($post['auto_status']);
    }

    if ($post['man_status']) {
      $tgt->set_Man_Status_ID($post['man_status']);
    }

    if ($post['data_status']) {
      $tgt->set_Data_Status_ID($post['data_status']);
    }

    if ($post['fp_cat1_status']) {
      $tgt->set_FP_Cat1_Status_ID($post['fp_cat1_status']);
    }

    if ($post['remove_existing']) {
      foreach ($tgt->checklists as $key => $chk) {
        unset($tgt->checklists[$key]);
      }
      $db->delete_Target_Checklists($tgt);
    }

    if ($post['checklists']) {
      $chks = array();
      foreach ($post['checklists'] as $key => $chk) {
        $tgt->checklists[] = $db->get_Checklist($chk)[0];
      }
    }

    $pp = ($post['post_process'] ? true : false);

    $db->save_Target($tgt, $pp);
  }

  header("Location: /ste");
}

include_once 'header.inc';
?>

<script src='ste_script.js' type='text/javascript'></script>

<style type="text/css">
  .header {
    width: auto;
    background-color: #31363C;
    display: table-cell;
  }

  .left_cat_header {
    width: 200px;
    float: left;
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
  }

  .not_reviewed,.not_applicable,.not_planned,.complete,.in_progress {
    text-align: center;
    width: 92px;
  }

  .not_reviewed {
    color: #fff;
    background-color: #ff0000;
  }

  .not_applicable {
    color: #000;
    background-color: #8db4e2;
  }

  .not_planned {
    color: #fff;
    background-color: #000;
  }

  .complete {
    color: #000;
    background-color: #92d050;
  }

  .in_progress {
    color: #000;
    background-color: #ffff66;
  }

  .checklists {
    display: inline;
    width: 300px;
    height: 150px;
  }

  .checklist_image {
    width: 32px;
    vertical-align: middle;
  }

  .notes {
    width: 100%;
  }

  #osSoftware {
    display: inline-block;
    width: 300px;
    text-align: right;
  }

  #availableOS {
    position: absolute;
    text-align: left;
    background-color: white;
    border: solid 1px black;
    z-index: 100;
    overflow-y: scroll;
    height: 250px;
    width: 400px;
  }

  .swmouseover {
    background-color:#1D57A0;
    color:#fff;
    cursor:pointer;
  }
</style>

<script type='text/javascript'>
  /**
   * Function to filter the checklists via AJAX
   *
   * @param {boolean} bln_hide_old
   */
  function filter_checklists(bln_hide_old) {
    if ($('#chk_filter').val().length < 3) {
      return;
    }

    $.ajax('/ajax.php', {
      data: {
        action: 'chk_filter',
        filter: $('#chk_filter').val(),
        hide_old: bln_hide_old
      },
      success: function (data) {
        $('#checklists option').remove();

        for (var x in data) {
          $('#checklists').append("<option " +
                  "value='" + data[x].id + "'>" +
                  data[x].name + " V" + data[x].ver + "R" + data[x].release + " (" + data[x].type + ")</option>");
        }
      },
      dataType: 'json',
      method: 'post'
    });
  }

  /**
   * Function to filter the operating systems via AJAX
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
        filter: $('#os_filter').val()
      },
      success: function (data) {
        $('#availableOS div').remove();
        $('#availableOS').show();
        for (var x in data) {
          $('#availableOS').append("<div sw_id='" + data[x].sw_id + "' cpe='" + data[x].cpe + "'>" + data[x].sw_string + "</div>");
        }

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
            $('#installedSoftware').append("<option value='" + $(this).attr('sw_id') + "' ondblclick='$(this).remove();'>" + $(this).html() + "</option>");
            $(this).remove();
          });
        });
      },
      dataType: 'json',
      method: 'post'
    });
  }

  /**
   * Function to validate the form before submitting
   */
  function validate_bulk() {
    $('#selected_tgts').val(JSON.stringify(sel_tgts));

    form.submit();
  }

  /**
   * Function to toggle to checkbox selections (what was check is now uncheck and visa versa)
   */
  function toggle_selection() {
    $('.tgt_chk').each(function () {
      $(this).prop('checked', !$(this).is(":checked"));
      update_tgt_chk(this);
    });
  }
</script>

<div id='wrapper'>
  <div id='main-wrapper'>
    <div class='12u' id='main-contnt'>
      <div id='tableContainer' class='tableContainer'>
        <form method='post' name='form'>
          <input type='hidden' name='action' value='update_bulk' />
          <input type='hidden' name='selected_tgts' id='selected_tgts' />
          <input type='hidden' name='ste' value='<?php print ($ste ? $ste : ''); ?>' />
          To change multiple targets:<br />
          <ol style='font-size:small;'>
            <li>Check the targets you want to change above</li>
            <li>Select only the fields below you want to change</li>
            <li>Click the Save button</li>
          </ol>

          <input type='button' name='update_bulk' value='Save' onclick='validate_bulk();' />

          <table>
            <tbody>
              <tr>
                <th>Category:</th>
                <td>
                  <select name='cat'>
                    <option value='0'>-- do not change --</option>
                    <?php
                    $cats = $db->get_STE_Cat_List($ste);
                    foreach ($cats as $cat):print $cat->get_Option();
                    endforeach;
                    ?>
                  </select>
                </td>
              </tr>
              <tr>
                <th>Operating System:</th>
                <td class="Control">
                  <input type='text' id='os_filter' style="display:inline;" title='CPE string' placeholder='Filter...' onkeyup="javascript:filter_os();" autocomplete="off" />
                  <span id="osSoftware">
                    <input type='hidden' name='osSoftware' />
                  </span>
                  <div id="availableOS" onmouseover="$(this).show();" onmouseout="$(this).hide();" style="display:none;"></div>
                </td>
              </tr>
              <tr>
                <th>Location:</th>
                <td><input type='text' name='location' placeholder='-- do not change --' /></td>
              </tr>
              <tr>
                <th>Automated Status:</th>
                <td>
                  <select name='auto_status'>
                    <option value='0'>-- do not change --</option>
                    <?php
                    foreach ($task_statuses as $key => $status):print "<option value='$key'>$status</option>";
                    endforeach;
                    ?>
                  </select>
                </td>
              </tr>
              <tr>
                <th>Manual Status:</th>
                <td>
                  <select name='man_status'>
                    <option value='0'>-- do not change --</option>
                    <?php
                    foreach ($task_statuses as $key => $status):print "<option value='$key'>$status</option>";
                    endforeach;
                    ?>
                  </select>
                </td>
              </tr>
              <tr>
                <th>Data Gathering Status:</th>
                <td>
                  <select name='data_status'>
                    <option value='0'>-- do not change --</option>
                    <?php
                    foreach ($task_statuses as $key => $status):print "<option value='$key'>$status</option>";
                    endforeach;
                    ?>
                  </select>
                </td>
              </tr>
              <tr>
                <th>FP/Cat1 Status:</th>
                <td>
                  <select name='fp_cat1_status'>
                    <option value='0'>-- do not change --</option>
                    <?php
                    foreach ($task_statuses as $key => $status):print "<option value='$key'>$status</option>";
                    endforeach;
                    ?>
                  </select>
                </td>
              </tr>
              <tr>
                <th title='Select to change' style='vertical-align:bottom;'>
                  Checklists:<br />
                  <input type='text' name='chk_filter' id='chk_filter' placeholder="Filter..." onkeyup="javascript:filter_checklists($('#hide_old').is(':checked'));" style='width:132px;' /><br />
                  Remove Existing Checklists:
                  <input type='checkbox' name='remove_existing' value='1' />
                </th>
                <td>
                  <select name='checklists[]' class='checklists' id="checklists" multiple='multiple'>
                    <?php
                    $all_chks = $db->get_Checklist();
                    foreach ($all_chks as $key => $chk):print $chk->print_Option();
                    endforeach;
                    ?>
                  </select>
                </td>
              </tr>
              <tr>
                <th>Post Processing?</th>
                <td>
                  <input type='checkbox' name='post_process' value='1' />
                </td>
              </tr>
            </tbody>
          </table>

          <table class=''>
            <thead>
              <tr>
                <th class="header" style='text-align:left;'>
                  <input type='button' value='Toggle Selection' onclick='javascript:toggle_selection();' />&nbsp;&nbsp;Name
                </th>
                <th class="header">OS</th>
                <th class="header">Location</th>
                <th class="header">Auto</th>
                <th class="header">Manual</th>
                <th class="header">Data</th>
                <th class="header">FP/Cat1</th>
                <th class="header">Checklists</th>
              </tr>
            </thead>

            <tbody id='targets'>
              <?php
              $odd = true;
              foreach ($tgts as $key => $tgt) {
                $os = $db->get_Software($tgt->get_OS_ID())[0];
                $auto_status = $task_statuses[$tgt->get_Auto_Status_ID()];
                $man_status = $task_statuses[$tgt->get_Man_Status_ID()];
                $data_status = $task_statuses[$tgt->get_Data_Status_ID()];
                $fpcat1_status = $task_statuses[$tgt->get_FP_Cat1_Status_ID()];

                $checklists = $db->get_Target_Checklists($tgt->get_ID());

                $icons = array();
                foreach ($checklists as $key2 => $chk) {
                  $current_icon = $chk->get_Icon();
                  if (array_key_exists($current_icon, $icons)) {
                    $icons[$current_icon]['title'] .= "\n- {$chk->get_Name()} V{$chk->get_Version()}R{$chk->get_Release()} ({$chk->get_type()})";
                  }
                  else {
                    $icons[$current_icon] = array(
                      'icon'  => $current_icon,
                      'title' => "- {$chk->get_Name()} V{$chk->get_Version()}R{$chk->get_Release()} ({$chk->get_type()})"
                    );
                  }
                }

                print "<tr class='" . ($odd ? 'odd' : 'even') . "_row'>" .
                    "<td><input type='checkbox' class='tgt_chk' value='{$tgt->get_ID()}' onclick='javascript:update_tgt_chk(this);'/>{$tgt->get_Name()}</td>" .
                    "<td>{$os->get_Name()} {$os->get_Version()}</td>" .
                    "<td>{$tgt->get_Location()}</td>" .
                    "<td class='" . strtolower(str_replace(' ', '_', $auto_status)) . "'>{$auto_status}</td>" .
                    "<td class='" . strtolower(str_replace(' ', '_', $man_status)) . "'>{$man_status}</td>" .
                    "<td class='" . strtolower(str_replace(' ', '_', $data_status)) . "'>{$data_status}</td>" .
                    "<td class='" . strtolower(str_replace(' ', '_', $fpcat1_status)) . "'>{$fpcat1_status}</td>" .
                    "<td>";

                foreach ($icons as $icon_key => $icon) {
                  print "<img src='/img/checklist_icons/$icon_key' class='checklist_image' title='{$icon['title']}' />";
                }

                print "</td>" .
                    "</tr>";

                $odd = !$odd;
              }
              ?>

            </tbody>
          </table>
        </form>
      </div>
    </div>
  </div>
</div>

<?php
include_once 'footer.inc';
