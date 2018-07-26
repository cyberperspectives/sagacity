/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * Array to store default headers in searches
 *
 * @type Array
 */
var default_headers = [
  {'title': 'STIG ID', 'data': 'stig_id'},
  {'title': 'VMS ID', 'data': 'vms_id'},
  {'title': 'Checklist Name', 'data': 'name'},
  {'title': 'Type', 'data': 'type'},
  {'title': 'PDI', 'data': 'pdi_id'},
  {'title': 'File Name', 'data': 'file'}
];

/**
 * Array to store headers for CVE searches
 *
 * @type Array
 */
var cve_headers = [
  {'title': 'PDI ID', 'data': 'pdi_id'},
  {'title': 'CVE ID', 'data': 'cve_id'},
  {'title': 'Description', 'data': 'desc'},
  {'title': 'Status', 'data': 'status'},
  {'title': 'Reference', 'data': 'ref'}
];

/**
 * Array to store headers for CPE searches
 *
 * @type Array
 */
var cpe_headers = [
  {'title': 'Man', 'data': 'man'},
  {'title': 'Name', 'data': 'name'},
  {'title': 'Ver', 'data': 'ver'},
  {'title': 'CPE', 'data': 'cpe'},
  {'title': 'String', 'data': 'sw_string'}
];

/**
 * Array to store headers for IAVM searches
 *
 * @type Array
 */
var iavm_headers = [
  {'title': 'PDI ID', 'data': 'pdi_id'},
  {'title': 'IAVM Notice', 'data': 'iavm'},
  {'title': 'Title', 'data': 'title'},
  {'title': 'Category', 'data': 'cat'},
  {'title': 'Link', 'data': 'link'}
];
var start = 0;
var table = null;

function query() {
  if (!$('#q').val()) {
    alert("Please enter something to search for");
    return;
  }
  if (table) {
    table.destroy();
  }
  if ($('#type').val() == 'cve')
    headers = cve_headers;
  else if ($('#type').val() == 'cpe')
    headers = cpe_headers;
  else if ($('#type').val() == 'iavm')
    headers = iavm_headers;
  else
    headers = default_headers;

  table = $('#results').DataTable({
    pageLength: 100,
    serverSide: true,
    stripeClasses: ['odd_row', 'even_row'],
    columns: headers,
    ajax: {
      beforeSend: function () {
        $('body').addClass('loading');
      },
      url: '/search.php',
      method: 'POST',
      data: {
        type: $('#type').val(),
        q: $('#q').val()
      },
      complete: function () {
        $('body').removeClass('loading');
      }
    }
  });
}

function open_stig(file, id) {
  $('#search_result').attr('src', '../reference/stigs/stig.php?file=' + file + '&vms=' + id);
  $('#search_result').animate({'opacity': '1.00'}, 300, 'linear');
  $('#search_result').css('display', 'block');
  view_box();
}

function open_pdi(pdi) {
  $('#search_result').attr('src', 'pdi.php?pdi=' + pdi);
  $('#search_result').animate({'opacity': '1.00'}, 300, 'linear');
  $('#search_result').css('display', 'block');
  view_box();
}

function view_box() {
  $('.backdrop').animate({
    'opacity': '.5'
  }, 300, 'linear');
  $('.backdrop').css('display', 'block');
  $('html, body').css({
    'overflow': 'hidden',
    'height': '100%'
  });
}

function close_box() {
  $('.backdrop, .box').animate({
    'opacity': '0'
  }, 300, 'linear', function () {
    $('.backdrop, .box').css('display', 'none');
  });

  $('html, body').css({
    'overflow': 'auto',
    'height': '100%'
  });

  if (mydz) {
    mydz.on('queuecomplete', function () {
      $('.dz-complete').remove();
      $('.dz-message').show();
    });
  }
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
      $('#release-date').val((dt.getMonth() + 1) + "/" + dt.getDate() + '/' + dt.getFullYear());

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

function save_checklist() {
  $.ajax('/ajax.php', {
    data: {
      action: 'save-checklist',
      id: $('#id').val(),
      name: $('#name').val(),
      desc: $('#description').val(),
      'rel-date': $('#release-date').val(),
      icon: $('#icon').val()
    },
    success: function (data) {
      if (data.error) {
        console.error(data.error);
      }
      else {
        alert(data.success);
      }
    },
    error: function (xhr, status, error) {
      console.error(error);
      alert(error);
    },
    dataType: 'json',
    method: 'post',
    timeout: 3000
  });
}

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
