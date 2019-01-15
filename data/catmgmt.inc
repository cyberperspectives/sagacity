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
global $db;
?>

<script
	src='/script/datatables/DataTables-1.10.9/js/jquery.dataTables.min.js'></script>
<link rel="stylesheet"
	href="/script/datatables/DataTables-1.10.9/css/jquery.dataTables.min.css" />
<link rel='stylesheet' href='/script/jquery-ui/jquery-ui.theme.min.css' />

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
<script type='text/javascript'>
    $(function () {
      $('#catalog').DataTable({
        'stripeClasses': ['odd_row', 'even_row']
      });
      $('.close, .backdrop').click(function () {
        close_box();
      });
      $('#release-date').datepicker();
    });

    function close_box() {
      $('.backdrop, .box').animate({
        'opacity': '0'
      }, 300, 'linear', function () {
        $('.backdrop, .box').css('display', 'none');
      });
    }

    function view_box() {
      $('.backdrop').animate({
        'opacity': '.5'
      }, 300, 'linear');
      $('.backdrop').css('display', 'block');
    }

    function get_cat_data(fname) {
      $('#popup').animate({
        'opacity': '1.00'
      }, 300, 'linear');
      $('#popup').css('display', 'block');
      view_box();

      $.ajax('/ajax.php', {
        data: {
          action: 'get-cat-data',
          'fname': fname
        },
        beforeSend: function () {
          $('#id').val('');
          $('#checklist-id').text('');
          $('#name').val('');
          $('#description').val('');
          $('#version').text('');
          $('#release').text('');
          $('#icon').val('');
          $('#type').text('');
          $('#software option').remove();
          $('#cpe').val('');
        },
        success: function (data) {
          $('#id').val(data.id);
          $('#checklist-id').text(data.checklist_id);
          $('#name').val(data.name);
          $('#description').val(data.description);
          $('#version').text(data.ver);
          $('#release').text(data.release);
          $('#icon').val(data.icon);
          $('#type').text(data.type);

          var dt = new Date(data.date.date);
          $('#release-date').val(dt.getMonth() + "/" + dt.getDate() + '/' + dt.getFullYear());

          for (var x in data.sw) {
            $('#software').append("<option id='" + data.sw[x].id + "'>" +
                    data.sw[x].man + " " + data.sw[x].name + " " + data.sw[x].ver +
                    "</option>");
          }

          $('#software option').dblclick(remove_Software);
        },
        error: function (xhr, status, error) {
          console.error(error);
        },
        timeout: 3000,
        method: 'post',
        dataType: 'json'
      });
    }

    function remove_Software() {
      $.ajax("/ajax.php", {
        data: {
          action: 'checklist-remove-software',
          chk_id: $('#id').val(),
          sw_id: $(this).attr('id')
        },
        success: function (data) {
          if (data.error) {
            alert(data.error);
          }
          else if (data.success) {
            alert(data.success);
          }
        },
        error: function (xhr, status, error) {
          console.error(error);
        },
        dataType: 'json',
        timeout: 3000,
        method: 'post'
      });

      $(this).remove();
    }

    function autocomplete_software() {
      if ($('#cpe').val().length < 3) {
        return;
      }

      $.ajax('/ajax.php', {
        data: {
          action: ($('#os').is(":checked") ? 'os_filter' : 'sw_filter'),
          filter: $('#cpe').val()
        },
        success: function (data) {
          $('#availableSoftware div').remove();
          for (var x in data) {
            $('#availableSoftware').append("<div sw_id='" + data[x].sw_id + "' cpe='" + data[x].cpe + "'>" + data[x].sw_string + "</div>");
          }
          $('#availableSoftware').show();

          $('#availableSoftware div').each(function () {
            $(this).on("mouseover", function () {
              $(this).addClass("swmouseover");
            });
            $(this).on("mouseout", function () {
              $(this).removeClass("swmouseover");
            });
            $(this).on("click", function () {
              add_software($(this).attr('sw_id'));
              $('#software').append("<option value='" + $(this).attr('sw_id') + "' ondblclick='remove_Software();$(this).remove();'>" + $(this).html() + "</option>");
              $(this).remove();
            });
          });
        },
        error: function (xhr, status, error) {
          console.error(error);
        },
        dataType: 'json',
        method: 'post',
        timeout: 5000
      });
    }

    function add_software(sw_id) {
      $.ajax('/ajax.php', {
        data: {
          action: 'checklist-add-software',
          'sw_id': sw_id,
          chk_id: $('#id').val()
        },
        success: function (data) {
          alert(data.status);
        },
        error: function (xhr, status, error) {
          console.error(error);
        },
        dataType: 'json',
        method: 'post',
        timeout: 3000
      });
    }
            </script>
<style type="text/css">
thead {
	background-image: linear-gradient(to bottom, #ECECEC, rgba(177, 177, 177, 0.72));
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
				<th>eChecklist</th>
			</tr>
		</thead>

		<tbody>
                  <?php
                $cat_scripts = $db->get_Catalog_Script();
                foreach ($cat_scripts as $cat_script) {
                    print <<<EOR
<tr>
    <td onclick='javascript:get_cat_data("{$cat_script->file_name}");'>
        <a href='javascript:void(0);'>{$cat_script->file_name}</a>
    </td>
    <td>{$cat_script->status}</td>
    <td>{$cat_script->start_time->format("Y-m-d H:i:s")}</td>
    <td>{$cat_script->perc_comp}</td>
    <td>{$cat_script->stig_count}</td>
    <td>
        <a href='/data/gen-echecklist.php?id={$cat_script->id}' target='_blank'><img src='/img/scan_types/echecklist.png' style='width:32px'; /></a>
    </td>
</tr>

EOR;
                }
                ?>
                </tbody>
	</table>
</div>

<div id='popup' class='box'>
	<div style='display: inline-block; width: 49%; vertical-align: top;'>
		<input type='hidden' id='id' />
		Checklist ID: <span id='checklist-id'></span><br />
		Name: <input type='text' id='name' /><br />
		Description: <input type='text' id='description' /><br />
		Version: <span id='version'></span><br />
		Release: <span id='release'></span><br />
		Release Date: <input type='text' id='release-date' /><br />
		Icon: <input type='text' id='icon' /><br />
		Type: <span id='type'></span>
	</div>

	<div style='display: inline-block; width: 49%;'>
		<select id='software' multiple size='10'></select><br />
		Add CPE: <input type='text' id='cpe' onkeyup='javascript:autocomplete_software();' />&nbsp;&nbsp;
		<label for='os'>OS?</label> <input type='checkbox' id='os' /><br />
		<div id="availableSoftware"></div>
	</div>
</div>

<div class="backdrop"></div>
