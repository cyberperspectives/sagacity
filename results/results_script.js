/**
 * File: results_script.js
 * Author: Ryan Prather
 * Purpose: Contain all JS for pages in the /results directory
 * Created: ?
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
 *  - ? - File created
 *  - Apr 5, 2017 - Formatting and added file header
 *  - Jan 16, 2018 - Changed scan deletion to an AJAX call, and changed confirmation boxes to use jQuery UI
 */

$(function () {
  $('.close, .backdrop').click(function () {
    close_box();
  });
});

function List_host(scan_id) {
  $('#host_list_frame').attr(
          'src',
          'host_list_iframe.php?ste=' + $('#ste').val() + '&scan_id='
          + scan_id);
  $('#host_list_div').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#host_list_div').css('display', 'block');
  view_box();
}

function close_box() {
  $('.backdrop, .box').animate({
    'opacity': '0'
  }, 300, 'linear', function () {
    $('.backdrop, .box').css('display', 'none');
  });
  $('.dz-complete').remove();
  $('.dz-message').show();
}

function view_box() {
  $('.backdrop').animate({
    'opacity': '.5'
  }, 300, 'linear');
  $('.backdrop').css('display', 'block');
}

function add_import() {
  if ($('#ste').val() < 1) {
    alert("Please select an ST&E");
    return;
  }
  $('#add_import').val($('#ste').val());
  $('#import').animate({
    'opacity': '1.00'
  }, 300, 'linear');
  $('#import').css('display', 'block');
  view_box();
}
