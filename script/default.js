/**
 * File: default.js
 * Author: Ryan Prather
 * Purpose: Contain functionality used across all pages
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
 *  - Sep 1, 2016 - Updated copyright
 *  - Oct 5, 2016 - Added positioning for the hidden copyright text
 *  - Oct 24, 2016 - Fixed positioning and scrolling of main content
 *  - Nov 7, 2016 - Formatting
 */

$(function () {
  resize_device_table();
});

/**
 * Resize the table when the window resizes
 */
function resize_device_table() {
  $('#copyright').css('top', $(window).height() - $('#copyright').height() - 20 + 'px');
  $('#copyright-text').css('top', $(window).height() - $('#copyright').height() - 115 + 'px');
  $('#copyright-text').css('left',
          ($(window).width() / 2) - ($('#copyright-text').width() / 2) + 'px');
  var cp_h = $('#copyright').height() + 20;
  var head_h = $('#header-wrapper').height();

  if ($('#tableContainer').length > 0) {
    $('#tableContainer').css('height', $(window).height() - 224 + 'px');
  }
  else if ($('#content').length > 0) {
    $('#content').css('height', $(window).height() - 144 + 'px');
  }
  else if ((/new\-target\.php/).test(window.location.href)) {
    $('.5grid-layout.5grid').eq(1).css('height', $(window).height() - 141 + 'px');
  }
  else {
    $('#wrapper').css('height', ($(window).height() - (cp_h + head_h)) + 'px');
    $('#main-wrapper').css('height', '100%');
    $('#main-content').css('height', ($(window).height() - (cp_h + head_h + 10)) + 'px').css(
            'overflow-y', 'auto').css('overflow-x', 'hidden');
  }
}

/**
 * window resize event handler
 */
window.onresize = function () {
  resize_device_table();
};

/**
 * Function to move individual items from one list to another
 *
 * @param sourceList
 * @param destinationList
 */
function moveItems(sourceList, destinationList) {
  if (typeof destinationList !== 'undefined') {
    var src = $('#' + sourceList + ' option:selected');
    var dest = $('#' + destinationList + ' option');
    if (dest.length > 0) {
      for (var x = 0; x < src.length; x++) {
        for (var y = 0; y < dest.length; y++) {
          if (src[x].text.toLowerCase() < dest[y].text.toLowerCase()) {
            $(dest[y]).before(src[x]);
            // src.length--;
            break;
          }

          if (y == dest.length - 1 && src[x].text.toLowerCase() >= dest[y].text.toLowerCase()) {
            $(dest[y]).after(src[x]);
          }
        }
      }
    }
    else {
      dest = $('#' + destinationList);
      for (var x = 0; x < src.length; x++) {
        $(dest).append(src[x]);
      }
    }
  }
  else {
    var src = $('#' + sourceList + ' option:selected');
    if (src.length > 0) {
      for (var x = 0; x < src.length; x++) {
        $(src[x]).remove();
      }
    }
  }
}

/**
 * Function to move all items from one list to another
 *
 * @param sourceList
 * @param destinationList
 */
function moveAll(sourceList, destinationList) {
  var x = 0;
  while (x < $('#' + destinationList + ' option').length) {
    while ($('#' + sourceList + ' option').length > 0) {
      var src_list = $('#' + sourceList + ' option')[0].text.toLowerCase();
      var dest_list = $('#' + destinationList + ' option')[x].text.toLowerCase();
      if (src_list < dest_list) {
        $($('#' + destinationList + ' option')[x]).before($($('#' + sourceList + ' option')[0]));
      }
      else {
        x++;
      }

      if ($('#' + sourceList + ' option').length == 0) {
        x = $('#' + destinationList + ' option').length;
      }
    }
  }
}

/**
 * Save Button Submit function for Target.php
 */
function validateTargetForm() {
  if (validateSelectedFields())
    $('#target').submit();
}

/**
 * Function to validate an IP address
 *
 * @param ip
 * @returns {Boolean}
 */
function validateIP(ip) {
  // Regular Expression that validates IPv4 format
  var re = /^DELETE|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}/;
  return re.test(ip);
}

/**
 * Function to validate the required fields in target.php
 *
 * @returns {Boolean}
 */
function validateSelectedFields() {
  var action = $('#action').val();
  // Controls
  var ste = $('select[name=ste]').val();
  if (ste == undefined) {
    ste = $("input[name='ste']").val();
  }
  var deviceName = $('#DeviceName').val();
  var os = $('#os_id');
  // Error Labels
  var valSTE = $('#validateSTE');
  var valDeviceName = $('#validateDeviceName');
  var valOS = $('#validateOS');
  var submit = true;

  if (!ste) {
    $(valSTE).text('ST&E is required');
    $(valSTE).show();
    submit = false;
  }
  else {
    $(valSTE).hide();
  }

  if (!deviceName) {
    $(valDeviceName).text('Device Name is required');
    $('#validateDeviceName').show();
    submit = false;
  }
  else {
    $(valDeviceName).hide();
  }

  if (!os || !os.val()) {
    if (submit && confirm("Would you like to set the OS to Generic?")) {
      $('#os_id').val($('#gen-os').val());
      $(valOS).hide();
    }
    else {
      $(valOS).text('OS is required');
      $(valOS).show();
      submit = false;
    }
  }
  else {
    $(valOS).hide();
  }

  if (submit) {
    $(valDeviceName).hide();
    $(valOS).hide();
    // Set the "Selected" attribute for each item in the multiselect
    // dropdown
    // This enables the items to be saved to the DB
    $('#applicableChecklists option').prop('selected', true);
    $('#installedSoftware option').prop('selected', true);

    if (action == 'insert') {
      return true;
    }

    // Check if the form is an "Update"
    if (action == 'update') {
      // If there any rows in the table
      if ($('#Interface').find('tr').length !== 0) {
        var result = true;

        // Loop thru each row
        $('#Interface tr').each(function () {
          // Find the input element with a 'name' attribute that
          // starts with 'ip'
          ip = $(this).find('input[name^=ip]');

          // Validate the value of 'ip' against the regex function
          // If the value of 'ip' passes validation
          if (validateIP(ip.val())) {
            // If the 'ip' failed validation at one point and now it
            // passes
            // Clear the formatting that indicates validation
            // failure
            ip.removeClass('highlight');
          }
          // If the 'ip' fails validation
          else {
            // show the error message
            $('#msg').show();
            // Add the highlight class to that 'ip' input element
            ip.addClass('highlight');
            // Any time an 'ip' fails validation 'result' is set to
            // false
            // When the user hits 'save' 'result' is set to 'true'
            // again
            // Every row is looped thru and if just one 'ip' fails
            // validation
            // 'result' is set to false
            result = false;
          }
        });
        // If 'result' is true, which means all 'ip(s)' passed
        // validation
        if (result) {
          // Hide the error message
          $('#msg').hide();
        }
        // If any 'ip(s)' fail validation the 'result' will be false and
        // the page won't 'save'
        // Only when 'result' is 'true' will the page 'save'
        return result;
      }
      else {
        return true;
      }
    }
  }
  return false;
}

/**
 * Function to set and update a cookie
 */
function setCookie(c_name, value) {
  var c_value = escape(value);
  document.cookie = c_name + "=" + c_value + ";path=/";
}

var origWidth, origHeight;

// ///////////////////// CUSTOMIZE HERE ////////////////////
// settings for tooltip
// Do you want tip to move when mouse moves over link?
var tipFollowMouse = true;
// Be sure to set tipWidth wide enough for widest image
var tipWidth = 600;
var offX = 20; // how far from mouse to show tip
var offY = -30;
var tipBorderColor = "#000080";
var tipBorderWidth = '3px';
var tipBorderStyle = "solid";
var tipPadding = 25;
var tipBgColor = "#FFFFFF";

// ////////////////// END OF CUSTOMIZATION AREA ///////////////////

// to layout image and text, 2-row table, image centered in top cell
// these go in var tip in doTooltip function
// startStr goes before image, midStr goes between image and text
var startStr = '<img width="200" src="';
var midStr = '" border="0">';

// //////////////////////////////////////////////////////////
// initTip - initialization for tooltip.
// Global variables for tooltip.
// Set styles
// Set up mousemove capture if tipFollowMouse set true.
// //////////////////////////////////////////////////////////

var tooltip, tipcss, mouseX, mouseY, tipOn, t1, t2;

/**
 * Function to initialize the tooltip popup
 */
function initTip() {
  tooltip = $('#tooltip');

  tooltip.css({
    'width': tipWidth + 'px',
    'background-color': tipBgColor,
    'padding': tipPadding + 'px',
    'border': tipBorderStyle + ' ' + tipBorderWidth + ' ' + tipBorderColor,
  });

  if (tooltip && tipFollowMouse) {
    document.onmousemove = trackMouse;
  }
}

/**
 * Function to track mouse movements
 *
 * @param evt
 */
function trackMouse(evt) {
  mouseX = window.event.clientX + $('body').scrollLeft();
  mouseY = window.event.clientY + $('body').scrollTop();
  if (tipOn)
    positionTip(evt);
}

/**
 * Function to show the tooltips
 *
 * @param evt
 * @param pdi_id
 */
function showTip(evt, pdi_id) {
  if (!tooltip) {
    return;
  }
  tipOn = true;
  tooltip.html($('#' + pdi_id).html());

  if (!tipFollowMouse)
    positionTip(evt);
}

/**
 * Helper function
 */
function movedMouse() {
  console.log("X=" + window.event.clientX + ", Y = " + window.event.clientY);
}

// ///////////////////////////////////////////////////////////
// positionTip function
// If tipFollowMouse set false, so trackMouse function
// not being used, get position of mouseover event.
// Calculations use mouseover event position,
// offset amounts and tooltip width to position
// tooltip within window.
// ///////////////////////////////////////////////////////////
function positionTip(evt) {
  mouseX = window.event.clientX + $('body').scrollLeft();
  mouseY = window.event.clientY + $('body').scrollTop();

  // tooltip width and height
  var tpWd = tooltip.width() || tooltip.offset().left;
  var tpHt = tooltip.height() || tooltip.offset().top;

  // document area in view (subtract scrollbar width for ns)
  var winWd = window.innerWidth - 20 + window.pageXOffset || $('body').width()
          + $('body').scrollLeft();
  var winHt = window.innerHeight - 20 + window.pageYOffset || $('body').height()
          + $('body').scrollTop();

  // check mouse position against tip and window dimensions
  // and position the tooltip
  if ((mouseX + offX + tpWd) > winWd)
    tooltip.css('left', mouseX - (tpWd + offX) + "px");
  else
    tooltip.css('left', mouseX + offX + "px");

  if ((mouseY + offY + tpHt) > winHt)
    tooltip.css('top', winHt - (tpHt + offY) + "px");
  else
    tooltip.css('top', mouseY + offY + "px");

  // if (!tipFollowMouse)
  tooltip.show(100);
}

function hideTip() {
  if (!tooltip)
    return;
  tooltip.hide(100);
  tipOn = false;
}
