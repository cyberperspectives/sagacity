<?php
/**
 * File: index.php
 * Author: Ryan Prather
 * Purpose: Index page for Data Management
 * Created: Sep 16, 2013
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
 *  - Sep 16, 2013 - File created
 *  - Sep 1, 2016 - Copyright updated and added new searching filters
 *  - Oct 10, 2016 - Added declaration and initialization for variables (bug #5)
 *  - Oct 24, 2016 - Removed onmouseover and onmouseout attributes to left nav buttons and added JS to add them after load
 * 					 Commented out reference, scan, and finding filter buttons
 *  - Nov 7, 2016 - Changed includes to include_once
 *  - Dec 12, 2016 - Added parsing for new constants (COMPANY, COMP_ADD, CREATOR, and LAST_MODIFIED_BY),
 *                   ensured all configuration elements are present, and updated jquery 1.10.2 to 1.11.3
 *  - Feb 15, 2017 - Formatting
 *  - Mar 22, 2017 - Changed catalog table to use DataTables instead of tablesorter JS library
 *  - May 13, 2017 - Added support for STIG checklist editing
 *                   Added support for editing the default output format for eChecklist exports
 *  - May 19, 2017 - Formatting, added saving audible results complete notification, added filtering to site, system, and STE saving
 *  - May 25, 2017 - Fixed search functionality
 *  - May 26, 2017 - Restored Enter key press for search execution
 *  - Jun 3, 2017 - Changed table stripping to use consistent classes across the system
 *  - Jan 20, 2018 - Fixed bug with system and site datatype for new ST&E
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';
include_once 'import.inc';

$db = new db();

/**
 * @todo add reset.php to left nav
 */
$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING);
$ste = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT);
if (!$ste) {
  $ste = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT);
}
$page = filter_input(INPUT_GET, 'p', FILTER_SANITIZE_STRING);

$ste_mgmt = '';
$ms_mgmt = '';
$cat_mgmt = '';
$site_mgmt = '';
$search = '';
$settings = '';
$tgt_search = '';
$ref_search = '';
$scan_search = '';
$find_search = '';

if (isset($action)) {
  if ($action == 'save-ste') {
    $defaults = array(
      'filter' => FILTER_SANITIZE_STRING,
      'flag'   => FILTER_NULL_ON_FAILURE
    );

    $args = array(
      'ste'         => array(
        'filter' => FILTER_VALIDATE_INT,
        'flag'   => FILTER_NULL_ON_FAILURE
      ),
      'system'      => array(
        'filter' => FILTER_VALIDATE_INT,
        'flag'   => FILTER_NULL_ON_FAILURE
      ),
      'site'        => array(
        'filter' => FILTER_VALIDATE_INT,
        'flag'   => FILTER_NULL_ON_FAILURE
      ),
      'start_date'  => $defaults,
      'end_date'    => $defaults,
      'assumptions' => $defaults,
      'constraints' => $defaults,
      'scope'       => $defaults,
      'ao'          => $defaults
    );

    $params = filter_input_array(INPUT_POST, $args);

    $sys = $db->get_System($params['system'])[0];
    $site = $db->get_Site($params['site'])[0];

    $ste = new ste($params['ste'], $sys, $site, $params['start_date'], $params['end_date'], null, null);
    $ste->set_Assumptions($params['assumptions']);
    $ste->set_Constraints($params['constraints']);
    $ste->set_Scope($params['scope']);
    $ste->set_AO($params['ao']);

    $db->save_STE($ste);
  }
  elseif ($action == 'save-system') {
    $defaults = array(
      'filter' => FILTER_SANITIZE_STRING,
      'flag'   => FILTER_NULL_ON_FAILURE
    );

    $args = array(
      'system'      => array(
        'filter' => FILTER_VALIDATE_INT,
        'flag'   => FILTER_NULL_ON_FAILURE
      ),
      'name'        => $defaults,
      'mac'         => $defaults,
      'class'       => $defaults,
      'description' => $defaults,
      'abbr'        => $defaults,
      'accred_type' => $defaults
    );

    $params = filter_input_array(INPUT_POST, $args);

    $system = new system($params['system'], $params['name'], $params['mac'], $params['class']);
    $system->set_Description($params['description']);
    $system->set_Abbreviation($params['abbr']);

    switch ($params['accred_type']) {
      case 'diacap':
        $system->set_Accreditation_Type(accrediation_types::DIACAP);
        break;
      case 'rmf':
        $system->set_Accreditation_Type(accrediation_types::RMF);
        break;
      case 'pci':
        $system->set_Accreditation_Type(accrediation_types::PCI);
        break;
      case 'nispom':
        $system->set_Accreditation_Type(accrediation_types::NISPOM);
        break;
      case 'hipaa':
        $system->set_Accreditation_Type(accrediation_types::HIPAA);
        break;
      case 'cobit':
        $system->set_Accreditation_Type(accrediation_types::COBIT);
        break;
      case 'sox':
        $system->set_Accreditation_Type(accrediation_types::SOX);
        break;
      default:
        $system->set_Accreditation_Type(accrediation_types::DIACAP);
    }

    $db->save_System($system);
    ?>

    <script src="/style/5grid/jquery-1.11.3.min.js"></script>
    <script type='text/javascript'>
      $(function () {
        if (confirm("Would you like to move on to site management?")) {
          location.href = "index.php?p=SiteMgmt";
        }
      });
    </script>

    <?php
  }
  elseif ($action == 'save-site') {
    $defaults = array(
      'filter' => FILTER_SANITIZE_STRING,
      'flag'   => FILTER_NULL_ON_FAILURE
    );
    $params = array(
      'site'      => array(
        'filter' => FILTER_VALIDATE_INT,
        'flag'   => FILTER_NULL_ON_FAILURE
      ),
      'name'      => $defaults,
      'address'   => $defaults,
      'city'      => $defaults,
      'state'     => $defaults,
      'zip'       => $defaults,
      'country'   => $defaults,
      'poc_name'  => $defaults,
      'poc_phone' => $defaults,
      'poc_email' => $defaults
    );
    $p = filter_input_array(INPUT_POST, $params);

    $site = new site($p['site'], $p['name'], $p['address'], $p['city'], $p['state'], $p['zip'], $p['country'], $p['poc_name'], $p['poc_email'], $p['poc_phone']);
    $db->save_Site($site);
    ?>

    <script src="/style/5grid/jquery-1.11.3.min.js"></script>
    <script type="text/javascript">
      $(function () {
        if (confirm("Would you like to move on to ST&E management?")) {
          location.href = "index.php?p=STEMgmt";
        }
      });
    </script>

    <?php
  }
  elseif ($action == 'Save Settings') {
    $params = array(
      'filter' => FILTER_SANITIZE_STRING,
      'flag'   => FILTER_NULL_ON_FAILURE
    );
    $args = array(
      'company'            => $params,
      'comp_add'           => $params,
      'last_modified_by'   => $params,
      'creator'            => $params,
      'log_level'          => $params,
      'flatten_echecklist' => array(
        'filter' => FILTER_VALIDATE_BOOLEAN
      ),
      'wrap_text'          => array(
        'filter' => FILTER_VALIDATE_BOOLEAN
      ),
      'notifications'      => array(
        'filter' => FILTER_VALIDATE_BOOLEAN
      ),
      'port_limit'         => array(
        'filter'  => FILTER_VALIDATE_INT,
        'flag'    => FILTER_REQUIRE_ARRAY,
        'options' => array('max_range' => 10000)
      ),
      'max_result_import'  => array(
        'filter'  => FILTER_VALIDATE_INT,
        'flag'    => FILTER_REQUIRE_ARRAY,
        'options' => array('max_range' => 20)
      ),
      'output_format'      => array(
        'filter'  => FILTER_VALIDATE_REGEXP,
        'flag'    => FILTER_NULL_ON_FAILURE,
        'options' => array('regexp' => "/xlsx|xls|html|csv|pdf|ods/")
      )
    );
    $fields = filter_input_array(INPUT_POST, $args);
  }
}

if ($page) {
  if ($page == 'STEMgmt' || $page == 'EditSTE') {
    $all_systems = $db->get_System();
    $all_sites = $db->get_Site();
    $title_prefix = "ST&amp;E Mgmt";
    $ste_mgmt = "style='color:#FFF;'";
  }
  elseif ($page == 'MSMgmt' || $page == 'EditMS') {
    $ms_mgmt = "style='color:#FFF;'";
    $title_prefix = "System Mgmt";
    $all_systems = $db->get_System();
  }
  elseif ($page == 'SiteMgmt' || $page == 'EditSite') {
    $site_mgmt = "style='color:#FFF;'";
    $title_prefix = "Site Mgmt";
    $all_sites = $db->get_Site();
  }
  elseif ($page == 'CatMgmt') {
    $cat_mgmt = "style='color:#FFF;'";
    $title_prefix = "Catalog Mgmt";
  }
  elseif ($page == 'Settings') {
    $settings = "style='color:#FFF;'";
    $title_prefix = "Settings";
  }
  elseif ($page == 'TgtSearch') {
    $tgt_search = "style='color:#fff;'";
    $title_prefix = "Target Search";
  }
  elseif ($page == 'RefSearch') {
    $ref_search = "style='color:#fff;'";
    $title_prefix = "Reference Search";
  }
  elseif ($page == 'ScanSearch') {
    $scan_search = "style='color:#fff;'";
    $title_prefix = "Scan Search";
  }
  elseif ($page == 'FindSearch') {
    $find_search = "style='color:#fff;'";
    $title_prefix = "Finding Search";
  }
  elseif ($page == 'Search') {
    $title_prefix = "Search";
    $search = "style='color:#FFF;'";
  }
}

include_once 'header.inc';
?>

<style type="text/css">
  nav {
    width: 15%;
    float: left;
  }

  nav div {
    width: 93%;
    background-color: #3992e7;
    margin: 2px 0;
    padding-left: 5px;
    border-radius: 5px;
  }

  .sub {
    color: #041e4d;
    text-decoration: none;
    width: 170px;
    margin: 4px 0;
    padding-left: 5px;
    border-radius: 5px;
    background-image: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#8FBFEE),
      to(#5B7CC2));
    background-image: -moz-linear-gradient(top, #8FBFEE, #5B7CC2);
    background-image: -ms-linear-gradient(top, #8FBFEE, #5B7CC2);
    background-image: -o-linear-gradient(top, #8FBFEE, #5B7CC2);
    box-shadow: inset 0px 0px 0px 2px #FFF, 0px 2px 2px 0px;
    display: block;
  }

  .sub_mouseover {
    background-image: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#7198BE),
      to(#1B449B));
    background-image: -moz-linear-gradient(top, #7198BE, #1B449B);
    background-image: -ms-linear-gradient(top, #7198BE, #1B449B);
    background-image: -o-linear-gradient(top, #7198BE, #1B449B);
  }

  #content {
    width: 82%;
    float: left;
    border: solid 3px #AFB5BB;
    border-radius: 7px;
    height: 650px;
    padding: 0 10px;
    overflow-y: scroll;
  }
</style>

<div id='wrapper'>
  <div id='main-wrapper'>
    <div class='12u' id='main-content'>
      <div class='5grid-layout'>
        <nav class="mobileUI-site-nav">
          <a href="/data/?p=MSMgmt"
             class="sub" <?php print $ms_mgmt; ?>>System Management</a>
          <a href="/data/?p=SiteMgmt"
             class="sub" <?php print $site_mgmt; ?>>Site Management</a>
          <a href="/data/?p=STEMgmt"
             class="sub" <?php print $ste_mgmt; ?>>ST&amp;E Management</a>
          <a href="/data/?p=CatMgmt"
             class="sub" <?php print $cat_mgmt; ?>>Catalog Management</a>
          <a href="/data/?p=Settings"
             class="sub" <?php print $settings; ?>>Settings</a>
          <a href="/data/?p=TgtSearch"
             class="sub" <?php print $tgt_search; ?>>Target Search</a>
          <!--
                    <a href="/data/?p=RefSearch"
                      class="sub" <?php print $ref_search; ?>>Reference Search</a>
                    <a href="/data/?p=ScanSearch"
                      class="sub" <?php print $scan_search; ?>>Scan Search</a>
                    <a href="/data/?p=FindSearch"
                      class="sub" <?php print $find_search; ?>>Finding Searcch</a>
          -->
          <a href="/data/?p=Search" class="sub" <?php print $search; ?>>Search</a>
        </nav>
        <div id='content' style='<?php
        if ($page == 'Search') {
          print 'position:relative;';
        }
        ?>'>
               <?php
               if ($page == 'STEMgmt' || $page == 'EditSTE') {
                 include_once 'stemgmt.inc';
               }
               elseif ($page == 'MSMgmt' || $page == 'EditMS') {
                 include_once 'sysmgmt.inc';
               }
               elseif ($page == 'SiteMgmt' || $page == 'EditSite') {
                 include_once 'sitemgmt.inc';
               }
               elseif ($page == 'TgtSearch') {
                 include_once 'tgtsearch.inc';
               }
               elseif ($page == 'RefSearch') {
                 include_once 'refsearch.inc';
               }
               elseif ($page == 'ScanSearch') {
                 include_once 'scansearch.inc';
                 print "<div id='scan-filter-results'></div>" .
                     "<div id='load-more'>" .
                     "<a href='javascript:void(0);' onclick='load_more=true;execute_filter();'>Load More...</a>" .
                     "</div>";
               }
               elseif ($page == 'FindSearch') {
                 include_once 'findsearch.inc';
               }
               elseif ($page == 'Settings') {
                 include_once 'settings.inc';
               }
               elseif ($page == 'CatMgmt') {
                   include_once 'catmgmt.inc';
          }
          elseif ($page == 'Search') {
            $q = filter_input(INPUT_POST, 'q', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
            $type = '';

            if (strpos($q, '=') !== false) {
              list($type, $q) = explode("=", $q);
            }
            ?>

            <script src='/script/datatables/DataTables-1.10.9/js/jquery.dataTables.min.js'></script>
            <link rel="stylesheet" href="/script/datatables/DataTables-1.10.9/css/jquery.dataTables.min.css" />
            <link rel='stylesheet' href='/script/jquery-ui-1.11.4/jquery-ui.min.css' />
            <script type='text/javascript'>
                  var default_headers = [
                    {'title': 'STIG ID', 'data': 'stig_id'},
                    {'title': 'VMS ID', 'data': 'vms_id'},
                    {'title': 'Checklist Name', 'data': 'name'},
                    {'title': 'Type', 'data': 'type'},
                    {'title': 'PDI', 'data': 'pdi_id'},
                    {'title': 'File Name', 'data': 'file'}
                  ];

                  var cve_headers = [
                    {'title': 'PDI ID', 'data': 'pdi_id'},
                    {'title': 'CVE ID', 'data': 'cve_id'},
                    {'title': 'Description', 'data': 'desc'},
                    {'title': 'Status', 'data': 'status'},
                    {'title': 'Reference', 'data': 'ref'}
                  ];

                  var cpe_headers = [
                    {'title': 'Man', 'data': 'man'},
                    {'title': 'Name', 'data': 'name'},
                    {'title': 'Ver', 'data': 'ver'},
                    {'title': 'CPE', 'data': 'cpe'},
                    {'title': 'String', 'data': 'sw_string'}
                  ];

                  var iavm_headers = [
                    {'title': 'PDI ID', 'data': 'pdi_id'},
                    {'title': 'IAVM Notice', 'data': 'iavm'},
                    {'title': 'Title', 'data': 'title'},
                    {'title': 'Category', 'data': 'cat'},
                    {'title': 'Link', 'data': 'link'}
                  ];
                  var start = 0;
                  var table = null;
                  $(function () {
                    $('.close, .backdrop').click(function () {
                      close_box();
                    });
                    $('#q').keyup(function (e) {
                      start = 0;
                      var code = e.which;
                      if (code == 13)
                        query();
                    });
                    if ($('#q').val()) {
                      query();
                    }
                  });

                  function query() {
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
                  }
            </script>

            <?php
            $waiting = rand(1, 7);
            ?>

            <style type='text/css'>
              #search_tip {
                display: none;
                z-index: 1000;
                background-color: #FFE681;
                color: #000;
                width: 200px;
                font-size: 16px;
                padding: 4px;
                border: solid 1px black;
                line-height: 1em;
                position: absolute;
              }
              body.loading {
                overflow: hidden;
              }
              body.loading .modal {
                display: block;
              }
              .modal {
                display: none;
                position: fixed;
                z-index: 1000;
                top: 0;
                left: 0;
                height: 100%;
                width: 100%;
                background: rgba( 255, 255, 255, .8 ) url('/img/waiting/waiting_<?php print $waiting; ?>.gif') 50% 50% no-repeat;
                background-size: 256px;
              }
            </style>

            <form method='post' action='#' onsubmit='return false;'>
              <select id='type'>
                <option value=''>Filter</option>
                <option value='cpe' <?php print (strtolower($type) == 'cpe' ? 'selected' : ''); ?>>CPE</option>
                <option value='cve' <?php print (strtolower($type) == 'cve' ? 'selected' : ''); ?>>CVE</option>
                <option value='ia' <?php print (strtolower($type) == 'ia' ? 'selected' : ''); ?>>IA Controls</option>
                <option value='iavm' <?php print (strtolower($type) == 'iavm' ? 'selected' : ''); ?>>IAVM</option>
                <option value='nessus' <?php print (strtolower($type) == 'nessus' ? 'selected' : ''); ?>>Nessus</option>
                <option value='stig' <?php print (strtolower($type) == 'stig' ? 'selected' : ''); ?>>STIG</option>
                <option value='vms' <?php print (strtolower($type) == 'vms' ? 'selected' : ''); ?>>VMS</option>
              </select>
              <input type='text' name='q' id='q' <?php print ($q ? "value='$q'" : ""); ?> placeholder='Search...' /><br />

              <input type='button' class='button' name='search' value='Search' onclick='javascript:query();' />
            </form>

            <div>
              <table id='results' class='display'>
                <thead></thead>
                <tbody></tbody>
              </table>
            </div>

            <?php
          }
          ?>
        </div>
      </div>
    </div>
  </div>
</div>

<script type='text/javascript'>
  $(function () {
    $('.sub').mouseover(function () {
      $(this).addClass('sub_mouseover');
    });
    $('.sub').mouseout(function () {
      $(this).removeClass('sub_mouseover');
    });
  });
</script>

<iframe id='search_result' class='box' style='width: 80%; height: 80%; top: 10%; left: 10%;'></iframe>

<div class="backdrop"></div>

<div class='modal'></div>

<?php
include_once 'footer.inc';
