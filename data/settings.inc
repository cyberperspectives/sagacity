<?php
/**
 * File: settings.inc
 * Author: Ryan Prather
 * Purpose: Allows the changing of system settings
 * Created: Jan 6, 2015
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
 *  - Jan 6, 2015 - File created
 *  - Sep 1, 2016 - Copyright updated
 *      Added max # of results scans to import simultaneously
 *  - Oct 24, 2016 - Fixed MAX_IMPORT constant and added PHP_CONF constant
 *  - Nov 16, 2016 - Changed LOG_LEVEL to check for E_* constants instead of strings
 *  - Dec 12, 2016 - Ensured all configuration items are populated here, added company data for eChecklist exports
 *  - Feb 15, 2017 - Formatting and changed NESSUS constant
 *  - May 13, 2017 - Added support for editing the default output format for E-Checklist exports
 *  - May 19, 2017 - Added audible notification setting
 *  - May 25, 2017 - Fixed typo
 */
$db = new db();
$settings = $db->get_Settings(['cpe-load-date', 'cve-load-date', 'stig-load-date', 'nasl-load-date']);
$cpe_date = (isset($settings['cpe-load-date']) ? new DateTime($settings['cpe-load-date']) : null);
$cve_date = (isset($settings['cve-load-date']) ? new DateTime($settings['cve-load-date']) : null);
$stig_date = (isset($settings['stig-load-date']) ? new DateTime($settings['stig-load-date']) : null);
$nasl_date = (isset($settings['nasl-load-date']) ? new DateTime($settings['nasl-load-date']) : null);
?>

<div style="width:49%;display:inline-block;">
  <form action="index.php/?p=Settings" method="post">
    <input type='hidden' name='action' value='Save Settings' />
    <?php
    if (isset($settings_saved)) {
      print $settings_saved;
    }
    ?>
    Company: <input type="text" name="company" value="<?php print COMPANY; ?>" /><br />
    Company Address: <input type="text" name="comp_add" value="<?php print COMP_ADD; ?>" /><br />
    Last Modified By: <input type="text" name="last_modified_by" value="<?php print LAST_MODIFIED_BY; ?>" /><br />
    Creator: <input type="text" name="creator" value="<?php print CREATOR; ?>" /><br /><br />

    Log level:
    <select name="log_level">
      <option <?php print (LOG_LEVEL == E_DEBUG) ? "selected" : null; ?>>DEBUG</option>
      <option <?php print (LOG_LEVEL == E_NOTICE) ? "selected" : null; ?>>NOTICE</option>
      <option <?php print (LOG_LEVEL == E_WARNING) ? "selected" : null; ?>>WARNING</option>
      <option <?php print (LOG_LEVEL == E_ERROR) ? "selected" : null; ?>>ERROR</option>
    </select><br /><br />

    Flatten eChecklist: <input type="checkbox" name="flatten_echecklist" <?php print (FLATTEN ? "checked" : null); ?> /><br />
    Wrap eChecklist Check Contents: <input type="checkbox" name="wrap_text" <?php print (WRAP_TEXT ? "checked" : null); ?> /><br />
    Audible Notifications: <input type='checkbox' name='notifications' <?php print (NOTIFICATIONS ? "checked" : null); ?> /><br /><br />

    Port Ingestion Limit: <input type="number" name="port_limit" value="<?php print PORT_LIMIT; ?>" min="0" max="10000" /><br />
    Max # of Result Scans: <input type="number" name="max_result_import" value="<?php print MAX_RESULTS; ?>" min="1" max="20" /><br />
    Output Format:
    <select name="output_format">
      <option value="xlsx" <?php print (ECHECKLIST_FORMAT == 'xlsx' ? "selected" : null); ?>>Microsoft Excel 2007+ (.xlsx)</option>
      <option value="xls"<?php print (ECHECKLIST_FORMAT == 'xls' ? "selected" : null); ?>>Microsoft Excel 95-2003 (.xls)</option>
      <option value="ods"<?php print (ECHECKLIST_FORMAT == 'ods' ? "selected" : null); ?>>OpenDocument Format (.ods)</option>
      <?php /*
        <option value="html"<?php print (ECHECKLIST_FORMAT == 'html' ? "selected" : null); ?>>HTML (.html)</option>
        <option value="pdf"<?php print (ECHECKLIST_FORMAT == 'pdf' ? "selected" : null); ?>>Post-script Document (.pdf)</option>
        <option value="csv"<?php print (ECHECKLIST_FORMAT == 'csv' ? "selected" : null); ?>>Comma-separated files (.csv)</option>
       */ ?>
    </select>

    <br />

    <!--
      Nessus server: <input type="text" name="nessus_server" value="<?php print NESSUS_SVR; ?>" /><br />
      NMap binary path: <input type="text" name="nmap_path" value="<?php print NMAP_PATH; ?>" /><br />
    -->

    <input type="button" class='button' value="Save Settings" onclick='this.form.submit();' />
  </form>
</div>

<div style="width:49%;display:inline-block;">
  <table id="system-dates" style='width:100%;vertical-align:top;'>
    <thead>
      <tr>
        <th>Type</th>
        <th>Date</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>CPE's</td>
        <td><?php print (is_a($cpe_date, 'DateTime') && $cpe_date != new DateTime("1970-01-01 00:00:00") ? $cpe_date->format("M j, Y") : "Not Loaded"); ?></td>
      </tr>
      <tr>
        <td>CVE's</td>
        <td><?php print (is_a($cve_date, 'DateTime') && $cve_date != new DateTime("1970-01-01 00:00:00") ? $cve_date->format("M j, Y") : "Not Loaded"); ?></td>
      </tr>
      <tr>
        <td>STIG's</td>
        <td><?php print (is_a($stig_date, 'DateTime') && $stig_date != new DateTime("1970-01-01 00:00:00") ? $stig_date->format("M j, Y") : "Not Loaded"); ?></td>
      </tr>
      <tr>
        <td>NASL</td>
        <td><?php print (is_a($nasl_date, 'DateTime') && $nasl_date != new DateTime("1970-01-01 00:00:00") ? $nasl_date->format("M j, Y") : "Not Loaded"); ?></td>
      </tr>
    </tbody>
  </table>
</div>