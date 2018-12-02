/**
 * File: ste_script.js
 * Author: Ryan Prather
 * Purpose: To store all JavaScript for use by any script in this directory
 * Created: ?
 *
 * Portions Copyright 2016-2017: Cyber Perspectives LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - ? - File created
 *  - Sep 1, 2016 - Updated copyright and added other functionality
 *  - Oct 24, 2016 - Updated get_hosts and display_hosts function to use JSON instead of XML
 *  - Nov 21, 2016 - Removed timeout for retrieving hosts from a category and added spinner
 *  - Jan 30, 2017 - Formatting, added auto-categorization AJAX
 *  - Feb 15, 2017 - Removed style tag for 0 border around targets after retrieving from DB
 *  - Mar 4, 2017 - Changed AJAX to use /ajax.php instead of /cgi-bin/ajax.php
 *  - Apr 6, 2017 - Updating edit_cat code to simplify UI
 *  - Apr 7, 2017 - Finished edit category functionality
 *  - May 13, 2017 - Added export_ckl method to export CKL files from category header or target details page
 *  - May 19, 2017 - Simplified target selection code
 *  - May 26, 2017 - Added supporting code to delete target from category after clicking "Delete Host", also specified location where CKL files are placed upon export.
 *  - Jan 10, 2018 - Added new methods for /ste/stats.php and cleaned up
 *  - Jan 15, 2018 - Moved colums around, added target notes,
 Added getColorForPercentage method for sliding color scale
 *  - Apr 29, 2018 - Simplified get_hosts method and displays, formatting
 */

/**
 *
 */
var opts = {
  lines: 15,
  length: 18,
  width: 9,
  radius: 61,
  scale: 2,
  corners: 1,
  color: '#000',
  opacity: 0.2,
  rotate: 13,
  direction: 1,
  speed: 0.5,
  trail: 50,
  fps: 20,
  zIndex: 2e9,
  className: 'spinner',
  top: '50%',
  left: '50%',
  shadow: false,
  hwaccel: false,
  position: 'absolute'
};
var sel_tgts = [];

/**
 * Perform a couple checks onces the page completely loads
 */
$(function () {
  var target = document.getElementById('loading');
  var spinner = new Spinner(opts).spin(target);

  $('.close, .backdrop').click(function () {
    close_box();
  });

  $('.notes').click(function () {
    $(this).siblings('span').show();
  });

  $('.toggler').click(collapse_expand);
  $('.target-notes').click(get_target_notes);
  $('#save-tgt-notes').click(save_target_notes);
});

/**
 * Function to update a hidden element with the ID's of the selected targets
 *
 * @param chk
 */
function update_tgt_chk(chk) {
  if ($(chk).is(':checked'))
    sel_tgts.push($(chk).val());
  else {
    sel_tgts.splice($.inArray($(chk).val(), sel_tgts), 1);
  }
}

/**
 * Open the move to popup
 */
function open_move_to() {
  if ($('#ste').val() < 1) {
    alert("Please select an ST&E");
    return;
  }

  if ($(":checkbox:checked").length < 1) {
    alert("Please select a device to move");
    return;
  }

  $('#move_to').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#move_to').css('display', 'block');
  view_box();
}

/**
 * Function to open the edit category lightbox
 *
 * @param {number} cat_id
 */
function edit_cat(cat_id) {
  if ($('#ste').val() < 1) {
    alert("Please select an ST&E");
    return;
  }

  for (var x in $('#scan_sources option')) {
    $('#scan_sources option').eq(x).attr('selected', false);
  }

  var cat_name = $('#cat_name_' + cat_id).text();
  var matches = cat_name.match(/\s+\(([\d]+)\)\s+\(([^\d][ \w]+)\)|\s+\(([\d]+)\)/i);
  cat_name = cat_name.replace(/\s+\(([\d]+)\)\s+\(([^\d][ \w]+)\)|\s+\(([\d]+)\)/i, '');
  cat_name = cat_name.replace(/\s{2,}/g, '');
  $('#new_cat_name').val(cat_name);
  $('#selected_cat').val(cat_id);
  if (matches && typeof matches[2] !== 'undefined')
    $('#analyst').val(matches[2]);
  else
    $('#analyst').val('');
  var srcs = JSON.parse($('#cat_sources_' + cat_id).val());

  for (var x in srcs) {
    $('#src_' + srcs[x]).attr('selected', true);
  }

  $('#edit_cat').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#edit_cat').css('display', 'block');
  view_box();
}

/**
 *
 */
function merge_target() {
  $('#merge_target').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#merge_target').css('display', 'block');
  view_box();
}

/**
 * Open the delete category popup
 *
 * @param id
 */
function delete_cat(id) {
  if ($('#ste').val() < 1) {
    alert("Please select an ST&E");
    return;
  }
  if (!confirm("Are you sure you want to delete this category?  Currently assigned targets will be set to the 'Unassigned' category.")) {
    return;
  }

  $.ajax('/ajax.php', {
    data: {
      action: 'delete-cat',
      ste_id: $('#ste').val(),
      cat_id: id
    },
    success: function (data) {
      if (data.error) {
        alert(data.error);
      }
      else {
        location.reload();
      }
    },
    error: function (xhr, status, error) {
      console.error(error);
    },
    dataType: 'json',
    method: 'post',
    timeout: 3000
  });
}

function del_target() {
  if (!confirm("Are you sure you want to delete the target?  This will also delete all findings and interfaces for the selected targets and is irreversible")) {
    return;
  }
}

/**
 * Open the add category popup
 */
function add_cat() {
  if ($('#ste').val() < 1) {
    alert("Please select an ST&E");
    return;
  }
  $('#add_ste').val($('#ste').val());
  $('#add_cat').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#add_cat').css('display', 'block');
  view_box();
}

/**
 * Function to get category data from database
 *
 * @param cat_id
 */
function get_category(cat_id) {
  $.ajax('/ajax.php', {
    data: {
      action: 'get_category_details',
      'cat_id': cat_id
    },
    success: function (data) {
      $('#new_cat_name').val(data.name);
      for (var x in data.sources) {
        $('#src_' + data.sources[x].id).attr('selected', true);
      }
    },
    datatype: 'json',
    method: 'post'
  });
}

/**
 * Reset the backdrop and visible boxes
 */
function close_box() {
  $('.backdrop, .box').animate({
    'opacity': '0'
  }, 300, 'linear', function () {
    $('.backdrop, .box').css('display', 'none');
  });
}

/**
 * Set the backdrop so it's visible
 */
function view_box() {
  $('.backdrop').animate({
    'opacity': '.5'
  }, 300, 'linear');
  $('.backdrop').css('display', 'block');
}

/**
 * Function to validate that targets were selected
 *
 * @param chk
 * @returns {Boolean}
 */
function update_Status(chk) {
  if ($(chk).val() < 1)
    return false;

  if ($(":checkbox:checked").length < 1) {
    alert("Please select a device to update");
    return false;
  }

  return true;
}

/**
 * Function to collapse or expand the category group
 */
function collapse_expand() {
  var id = $(this).data('id');
  if(!$('.cat_' + id).length) {
    get_hosts(id);
  }

  $(this).toggleClass('fa-minus-square fa-plus-square');

  $('.cat_' + id).toggle(300);
}

/**
 * Function triggered when a target checkbox is clicked
 *
 * @param id
 */
function select(id) {
  $('.cat_' + id + ' input[type=checkbox]').each(function () {
    this.checked = !this.checked;
    update_tgt_chk(this);
  });
}

/**
 * Function to prompt the user for the analyst to assign to a category
 *
 * @param id
 */
function assign(id) {
  var analyst = prompt('Who do you want to assign this category to?\n\nEnter "none" to clear out assignment');
  if (analyst) {
    $('#analyst_' + id).val(analyst);
    $('#assign_' + id).submit();
  }
}

/**
 * Function to upload a host list file
 */
function upload_host_list() {
  if ($('#ste').val() < 1) {
    alert("Please select an ST&E");
    return;
  }
  $('#import_host_list').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#import_host_list').css('display', 'block');
  view_box();
}

/**
 * Function to retrieve the hosts within a specific category
 *
 * @param cat_id
 */
function get_hosts(cat_id) {
  $.ajax('/ajax.php', {
    data: {
      action: 'get_hosts',
      'cat_id': cat_id
    },
    beforeSend: function () {
      $('#loading,#waiting').show();
      $('#waiting').animate({'opacity': '0.5'}, 300, 'linear');
    },
    success: function (data) {
      if ($('#ops-page').val() == 'main') {
        display_ops_hosts(data);
      }
      else if ($('#ops-page').val() == 'stats') {
        display_stats_hosts(data);
      }
      else if ($('#ops-page').val() == 'task') {
        display_task_hosts(data);
      }
    },
    error: function (xhr, status, error) {
      console.error(error);
    },
    complete: function () {
      $('#loading,#waiting').hide();
      $('#waiting').animate({'opacity': '0'}, 300, 'linear');
    },
    dataType: 'json',
    method: 'post'
  });
}

function display_ops_hosts(hosts) {
  if (hosts.error) {
    console.error(hosts.error);
  }
  else {
    var cat_id = hosts.cat_id;
    var cat = $('#cat_' + cat_id);
    var odd = true;

    for (var x in hosts.targets) {
      $(cat).append(
              "<div class='" + (odd ? "odd_row" : "even_row") + " cat_" + cat_id + "'>" +
              "<span class='cat-cell' style='width:102px;text-align:left'>" +
              "<input type='checkbox' class='tgt-sel' value='" + hosts.targets[x].id + "' onclick='javascript:update_tgt_chk(this);' />" +
              "<a href='target.php?ste=" + hosts.targets[x].ste_id + "&tgt=" + hosts.targets[x].id + "' class='host' target='_blank'>" + hosts.targets[x].name + "</a>" +
              "<a href='target.php?ste=" + hosts.targets[x].ste_id + "&tgt=" + hosts.targets[x].id + "' class='ip' target='_blank'>" + hosts.targets[x].ip + "</a>" +
              "</span>" +
              "<span class='cat-cell' style='width:104px;line-height:1.25em;'>" + hosts.targets[x].os + "</span>" +
              "<span class='cat-cell' style='width:102px;'>" +
              (hosts.targets[x].location ? hosts.targets[x].location : "&nbsp;") +
              "</span>" +
              "<span class='cat-cell task-" + hosts.targets[x].auto.toLowerCase() + "' style='width:63px;text-align:center;'>" + hosts.targets[x].auto + "</span>" +
              "<span class='cat-cell task-" + hosts.targets[x].man.toLowerCase() + "' style='width:63px;text-align:center;'>" + hosts.targets[x].man + "</span>" +
              "<span class='cat-cell task-" + hosts.targets[x].data.toLowerCase() + "' style='width:63px;text-align:center;'>" + hosts.targets[x].data + "</span>" +
              "<span class='cat-cell task-" + hosts.targets[x].fp.toLowerCase() + "' style='width:63px;text-align:center;'>" + hosts.targets[x].fp + "</span>" +
              "<span class='cat-cell' style='width:147px;'>" +
              (hosts.targets[x].scans ? hosts.targets[x].scans : "&nbsp;") +
              "</span>" +
              "<span class='cat-cell' style='width:147px;'>" +
              (hosts.targets[x].chk ? hosts.targets[x].chk : "&nbsp;") +
              "</span>" +
              "<span class='cat-cell note' id='note_" + hosts.targets[x].id + "' style='width:346px;'>" + (hosts.targets[x].notes ? hosts.targets[x].notes : "&nbsp;") +
              "<i class='fas target-notes fa-pen-square' data-id='" + hosts.targets[x].id + "'> </i>" +
              "</span>" +
              "</div>"
              );

      odd = !odd;
    }

    $('#cat_' + cat_id + '_dl').val(1);
    $('.target-notes').click(get_target_notes);
    $('.fa-ellipsis-h').tooltip({
      classes: {
        'ui-tooltip': 'highlight'
      }
    });
  }
}

function display_stats_hosts(hosts) {
  if (hosts.error) {
    console.error(hosts.error);
  }
  else {
    var cat_id = hosts.cat_id;
    var cat = $('#cat_' + cat_id);
    var odd = true;

    for (var x in hosts.targets) {
      $(cat).after(
              "<div class='" + (odd ? "odd_row" : "even_row") + " cat_" + cat_id + "'>" +
              "<span class='cat-cell name' style='text-align:left'>" +
              "<input type='checkbox' class='tgt-sel' value='" + hosts.targets[x].id + "' onclick='javascript:update_tgt_chk(this);' />" +
              "<a href='target.php?ste=" + hosts.targets[x].ste_id + "&tgt=" + hosts.targets[x].id + "' class='host' target='_blank'>" + hosts.targets[x].name + "</a>" +
              "<a href='target.php?ste=" + hosts.targets[x].ste_id + "&tgt=" + hosts.targets[x].id + "' class='ip' target='_blank'>" + hosts.targets[x].ip + "</a>" +
              "</span>" +
              "<span class='cat-cell os' style='line-height:1.25em;'>" + hosts.targets[x].os + "</span>" +
              "<span class='cat-cell cat1 cat_I' title='Cat I Findings' style='text-align:center;'>" + hosts.targets[x].cat_1 + "</span>" +
              "<span class='cat-cell cat2 cat_II' title='Cat II Findings' style='text-align:center;'>" + hosts.targets[x].cat_2 + "</span>" +
              "<span class='cat-cell cat3 cat_III' title='Cat III Findings' style='text-align:center;'>" + hosts.targets[x].cat_3 + "</span>" +
              "<span class='cat-cell nf' title='Not a Finding' style='text-align:center;'>" + hosts.targets[x].nf + "</span>" +
              "<span class='cat-cell na' title='Not Applicable' style='text-align:center;'>" + hosts.targets[x].na + "</span>" +
              "<span class='cat-cell nr' title='Not Reviewed' style='text-align:center;'>" + hosts.targets[x].nr + "</span>" +
              "<span class='cat-cell comp' title='Percentage Compliant' style='text-align:center;background-color: " +
              getColorForPercentage(hosts.targets[x].comp) + ";'>" + (hosts.targets[x].comp.toFixed(2) * 100) + "%</span>" +
              "<span class='cat-cell assessed' title='Percentage Assessed' style='text-align:center;background-color: " +
              getColorForPercentage(hosts.targets[x].assessed) + ";'>" + (hosts.targets[x].assessed.toFixed(2) * 100) + "%</span>" +
              "<span class='cat-cell scans'>" +
              (hosts.targets[x].scans ? hosts.targets[x].scans : "&nbsp;") +
              "</span>" +
              "<span class='cat-cell checklists'>" +
              (hosts.targets[x].chk ? hosts.targets[x].chk : "&nbsp;") +
              "</span>" +
              "<span class='cat-cell note' id='note_" + hosts.targets[x].id + "'>" + hosts.targets[x].notes +
              "<i class='fas target-notes fa-pen-square' data-id='" + hosts.targets[x].id + "'> </i>" +
              "</span>" +
              "</div>"
              );

      odd = !odd;
    }

    $('#cat_' + cat_id + '_dl').val(1);
    $('.target-notes').click(get_target_notes);
    $('.fa-ellipsis-h').tooltip({
      classes: {
        'ui-tooltip': 'highlight'
      }
    });
  }
}

function display_task_hosts(hosts) {

}

function get_target_notes() {
  var id = $(this).data('id');
  $('#tgt-id').val(id);
  $.ajax('/ajax.php', {
    data: {
      action: 'get-target-notes',
      'tgt-id': id
    },
    success: function (data) {
      if (data.error) {
        alert(data.error);
      }
      else {
        $('#notes').val(data.notes);
        view_box();
      }
      $('#tgt-notes').animate({
        'opacity': '1.00'
      }, 300, 'linear');
      $('#tgt-notes').css('display', 'block');
    },
    error: function (xhr, status, error) {
      console.error(error);
    },
    dataType: 'json',
    method: 'post'
  });
}

function save_target_notes() {
  $.ajax('/ajax.php', {
    data: {
      action: 'save-target-notes',
      'tgt-id': $('#tgt-id').val(),
      'notes': $('#notes').val()
    },
    success: function (data) {
      if (data.error) {
        alert(data.error);
      }
      else {
        $('#note_' + $('#tgt-id').val()).html($('#notes').val() + "<i class='fas target-notes fa-pen-square' data-id='" + $("#tgt-id").val() + "'> </i>");
        $('.target-notes').click(get_target_notes);
        $('.fa-ellipsis-h').tooltip({
          classes: {
            'ui-tooltip': 'highlight'
          }
        });
        close_box();
      }
    },
    error: function (xhr, status, error) {
      console.error(error);
    },
    dataType: 'json',
    method: 'post'
  });
}

/**
 * Function to make AJAX call for system to autocategorize targets based on OS
 */
function auto_cat() {
  $.ajax('/ajax.php', {
    data: {
      ste: $('#ste').val(),
      action: 'auto-categorize'
    },
    beforeSend: function () {
      $('#loading,#waiting').show();
      $('#waiting').animate({'opacity': '0.5'}, 300, 'linear');
    },
    success: function (data) {
      location.reload();
    },
    error: function (xhr, status, error) {
      console.error(error);
    },
    complete: function () {
      $('#loading,#waiting').hide();
      $('#waiting').animate({'opacity': '0'}, 300, 'linear');
    },
    dataType: 'json',
    timeout: 5000,
    method: 'post'
  });
}

function export_ckl(cat_id, tgt_id) {
  if (!cat_id) {
    $.ajax('/ajax.php', {
      data: {
        ste: $('#ste').val(),
        tgt: tgt_id,
        action: 'export-ckl'
      },
      complete: function (xhr) {
        alert("Exporting target CKL files to document_root/tmp/ckl");
      },
      method: 'post'
    });
  }
  else {
    $.ajax('/ajax.php', {
      data: {
        ste: $('#ste').val(),
        cat: cat_id,
        action: 'export-ckl'
      },
      complete: function (xhr) {
        alert('Exporting CKL files to document_root/tmp/ckl');
      },
      method: 'post'
    });
  }
}

// Mister @Jacob's Anwser
var percentColors = [
  {pct: 0.0, color: {r: 0xff, g: 0x00, b: 0}},
  {pct: 0.5, color: {r: 0xff, g: 0xff, b: 0}},
  {pct: 1.0, color: {r: 0x00, g: 0xff, b: 0}}];

var getColorForPercentage = function (pct) {
  for (var i = 1; i < percentColors.length - 1; i++) {
    if (pct < percentColors[i].pct) {
      break;
    }
  }
  var lower = percentColors[i - 1];
  var upper = percentColors[i];
  var range = upper.pct - lower.pct;
  var rangePct = (pct - lower.pct) / range;
  var pctLower = 1 - rangePct;
  var pctUpper = rangePct;
  var color = {
    r: Math.floor(lower.color.r * pctLower + upper.color.r * pctUpper),
    g: Math.floor(lower.color.g * pctLower + upper.color.g * pctUpper),
    b: Math.floor(lower.color.b * pctLower + upper.color.b * pctUpper)
  };
  return 'rgb(' + [color.r, color.g, color.b].join(',') + ')';
  // or output as hex if preferred
}