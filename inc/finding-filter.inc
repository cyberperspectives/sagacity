<?php
/**
 * File: finding-filter.php
 * Author: Ryan
 * Purpose: This file contains all that is necessary for the display of the finding filter.
 *    When filtering, the results go into a dive with the id='finding-filter-results', place wherever desired.
 * Created: Sep 3, 2016
 *
 * Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 3, 2016 - File created
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 */
include_once 'database.inc';

if (!$db) {
  $db = new db();
}

$filters = $db->get_Filters('finding');
$col = 250;
$col2 = 398;

if (isset($finding_filter_width)) {
  $finding_filter_width -= 40;
  $col = floor($finding_filter_width / 5);
  $col2 = $col * 2;
}
else {
  $finding_filter_width = 1200;
}
?>

<script type='text/javascript'>
  function save_finding_filter() {
    var criteria = '';
    $('#filter option').each(function () {
      criteria += $(this).text() + "\n";
    });
    $.post(
            '/ajax.php',
            {
              'action': 'save_filter',
              'criteria': criteria,
              'type': 'finding',
              'name': $('#filter-name').val(),
            },
            save_filter_result,
            'text'
            );
  }

  function save_filter_result(data) {
    if (data == 'false') {
      alert('Filter saving failed');
    }
  }

  function add_filter() {
    if ($('#filter-options').val() == '0') {
      alert('Must select a filter option');
      return;
    }

    var op = ' = ';
    var op_str = ' IS ';

    if ($('#not').is(':checked') && $('#like').is(':checked')) {
      op = ' !~ ';
      op_str = ' NOT LIKE ';
    }
    else if ($('#not').is(':checked')) {
      op = ' != ';
      op_str = ' NOT EQUAL ';
    }
    else if ($('#like').is(':checked')) {
      op = ' ~= ';
      op_str = ' LIKE ';
    }

    var filter = '';
    switch ($('#filter-options').val()) {
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

  if (typeof window.collapse_expand_data === 'undefined') {
    window.collapse_expand_data = function (selection) {
      if ($('#' + selection + '-img').attr('src') == '/img/right-arrow.png') {
        $('#' + selection + '-img').attr('src', '/img/down-arrow.png');
      }
      else {
        $('#' + selection + '-img').attr('src', '/img/right-arrow.png');
      }

      $('#' + selection).toggle(300);
    };
  }

  function execute_filter() {
    if ($('#filter option').length == 0) {
      alert('Please add something to filter');
      console.error('Nothing to filter');
      return;
    }
    var criteria = '';
    $('#filter option').each(function () {
      criteria += $(this).text() + "\n";
    });

    $.post(
            '/ajax.php',
            {
              action: 'finding-filter',
              'criteria': criteria,
              start_count: $('#filter-start').val(),
              count: $('#filter-count').val(),
            },
            display_finding_filter_results,
            'html'
            );
  }

  function display_finding_filter_results(data) {
    if ($('#finding-filter-results').length == 0) {
      console.error("Cannot find div to populate targets in");
      return;
    }

    var odd = true;
    $('#finding-filter-results').html("");

    //$('#filter-start').val(parseInt($('#filter-start').val())+parseInt($('#filter-count').val()));

    $(data).find("finding").each(function () {
      odd = !odd;
    });
  }

  function retrieve_saved_filter() {
    $('#filter-start').val(0);
    $.post(
            '/ajax.php',
            {
              action: 'get-saved-filter',
              'type': 'finding',
              name: $('#saved-filter').val(),
            },
            display_saved_filter,
            'text'
            );
  }

  function display_saved_filter(data) {
    $('#filter').html(data);
  }


  function change_filter_option() {
    $('.filter').hide();
    switch ($('#filter-options').val()) {
      default:
        $('#filter-text').show();
    }
  }


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
</script>


<style type='text/css'>
  .title {
    width: <?php print $finding_filter_width; ?>px;
    background-color: #808080;
    font-size: 14pt;
    font-weight: bolder;
    text-decoration: italic;
    text-align: left;
    padding-left: 20px;
    color: black;
    margin-top: 5px;
    border: solid 1px black;
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

  .table-header {
    width: <?php print($finding_filter_width += 22); ?>px;
    text-align: center;
  }

  #finding-filter-results {
    width: <?php print $finding_filter_width; ?>px;
  }
</style>

<div class='title'>
  <img id='cat-filter-img' src='/img/right-arrow.png' onclick="javascript:collapse_expand_data('cat-filter');" style='width:20px;' />
  &nbsp;&nbsp;Finding Filter...
</div>

<div id='cat-filter' style='display:none;'>
  <input type='hidden' id='filter-start' value='0' />
  <div class='col'>
    <select id='filter-options' onchange="javascript:change_filter_option();" style='width:175px;'>
      <option value='0'>Filter options...</option>
      <option value='target'>Target</option>
      <option value='stig'>STID ID</option>
      <option value='cve'>CVE</option>
      <option value='status'>Status</option>
      <option value='cpe'>CPE</option>
      <option value='cc'>Check Contents</option>
      <option value='st'>Short Title</option>
      <option value='desc'>Description</option>
      <option value='notes'>Notes</option>
    </select><br />

    <input type='text' class='filter' id='filter-text' placeholder='Filter...' /><br />

    <label for='not'>Not?</label>
    <input type='checkbox' id='not' value='1' />

    <label for='like'>Like?</label>
    <input type='checkbox' id='like' value='1' />

    <input type='button' id='add' value='Add' onclick="javascript:add_filter();" />
  </div>

  <div class='col2'>
    <select name='filter[]' id='filter' multiple size='4' style="width:<?php print $col2 - 15; ?>px;height:110px;" title="Double-click to remove filter" ondblclick="$('#filter option:selected').remove();">
    </select>
  </div>

  <div class='col' style='text-align: center;'>
    <select id='filter-count'>
      <option value='0'>Filter Count</option>
      <option value='5'>5</option>
      <option value='10'>10</option>
      <option value='25'>25</option>
      <option value='50'>50</option>
      <option value='100'>100</option>
      <option value='all'>All</option>
    </select><br />

    <input type='button' name='run-filter' value='Filter...' onclick="javascript:execute_filter();" />
  </div>

  <div class='col' style='text-align: right;'>
    <select name='saved-filter' id='saved-filter' onchange="javascript:retrieve_saved_filter();">
      <option value='0'>Saved Filters...</option>
      <?php
      foreach ($filters as $filter) {
        print "<option>" . $filter['name'] . "</option>";
      }
      ?>
    </select><br />

    <input type='text' name='filter-name' id='filter-name' /><br />
    <input type='button' name='save-filter' value='Save Filter' onclick="javascript:save_finding_filter();" />
  </div>
</div>

<div id='finding-filter-results'></div>
<div id='load-more'>
  <a href='javascript:void(0);' onclick='load_more = true;execute_filter();'>Load More...</a>
</div>
