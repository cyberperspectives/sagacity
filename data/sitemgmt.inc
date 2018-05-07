<?php
/**
 * File: sitemgmt.inc
 * Author: Ryan Prather
 * Purpose: For adding or editing sites
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
 *  - May 19, 2017 - Migrated to filtering and changed save button to match buttons throughout
 */
$page = filter_input(INPUT_GET, 'p', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$site_id = filter_input(INPUT_POST, 'site', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

if ($page == 'SiteMgmt') {
  ?>

  <form method='post' action='?p=EditSite'>
    Select Site:<br />
    <select name='site' onchange="this.form.submit();">
      <option value='0'>-- Please Select A Site --</option>
      <?php
      foreach ($all_sites as $site) :
        print $site->get_Option();
      endforeach
      ;
      ?>
      <option value='new'>New...</option>
    </select>
  </form>

  <?php
}
elseif ($page == 'EditSite' && $site_id) {
  $selected_site = $db->get_Site($site_id);
  if (is_array($selected_site) && count($selected_site) && isset($selected_site[0]) && is_a($selected_site[0], 'site')) {
    $selected_site = $selected_site[0];
  }
  else {
    die("Couldn't find the selected site");
  }
  ?>

  <form method='post' action='?p=EditSite'>
    Select Site: <select name='site' onchange="this.form.submit();">
      <option value='0'>-- Please Select A Site --</option>
      <?php
      foreach ($all_sites as $site) :
        $selected = $site_id == $site->get_Id() ? true : false;
        print $site->get_Option($selected);
      endforeach
      ;
      ?>
      <option value='new'>New...</option>
    </select>
  </form>

  <form method='post' action='?p=SiteMgmt'>
    <input type='hidden' name='site' value='<?php print $site_id; ?>' />
    <input type='hidden' name='action' value='save-site' />
    Name:
    <input type='text' name='name'
           value='<?php print $selected_site->get_Name(); ?>' /><br />
    Address:
    <input type='text' name='address'
           value='<?php print $selected_site->get_Address(); ?>' /><br />
    City:
    <input type='text' name='city'
           value='<?php print $selected_site->get_City(); ?>' /><br />
    State:
    <select name='state'>
      <?php
      foreach ($STATES as $key => $val) {
        print "<option value='$key'" . ($key == $selected_site->get_State() ? " selected" : "") . ">$val</option>";
      }
      ?>
    </select><br />
    Postal Code: <input type='text' name='zip'
                        value='<?php print $selected_site->get_Zip(); ?>' /><br />
    Country: <select name='country'>
      <?php
      foreach ($Countries as $key => $val) {
        print "<option value='$key'" . ($key == $selected_site->get_Country() ? " selected" : "") . ">$val</option>";
      }
      ?>
    </select><br />
    POC Name:
    <input type='text' name='poc_name'
           value='<?php print $selected_site->get_POC_Name(); ?>' /><br />
    POC E-mail:
    <input type='text' name='poc_email'
           value='<?php print $selected_site->get_POC_Email(); ?>' /><br />
    POC Phone:
    <input type='text' name='poc_phone'
           value='<?php print $selected_site->get_POC_Phone(); ?>' /><br />

    <input type='button' class='button' value='Save Site' onclick='this.form.submit();' />
  </form>

  <?php
}
elseif ($page == 'EditSite' && !$site_id) {
  ?>

  <form method='post' action='?p=SiteMgmt'>
    <input type='hidden' name='action' value='save-site' />
    Name: <input type='text' name='name' /><br />
    Address: <input type='text' name='address' /><br />
    City: <input type='text' name='city' /><br />
    State: <select name='state'>
      <?php
      foreach ($STATES as $key => $val): print "<option value='$key'>$val</option>";
      endforeach;
      ?>
    </select><br />
    Postal Code: <input type='text' name='zip' /><br />
    Country: <select name='country'>
      <?php
      foreach ($Countries as $key => $val): print "<option value='$key'>$val</option>";
      endforeach;
      ?>
    </select><br />
    POC Name: <input type='text' name='poc_name' /><br />
    POC E-mail: <input type='text' name='poc_email' /><br />
    POC Phone: <input type='text' name='poc_phone' /><br />
    <input type='button' class='button' value='Save Site' onclick='this.form.submit();' />
  </form>

  <?php
}