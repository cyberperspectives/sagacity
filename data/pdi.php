<?php
/**
 * File: pdi.php
 * Author: Ryan Prather
 * Purpose: Get a PDI and display all associated information
 * Created: Feb 13, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Feb 13, 2014 - File created
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$pdi_id = filter_input(INPUT_GET, 'pdi', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

if (!$pdi_id) {
  die("Need a valid PDI");
}

$db = new db();

$pdi = $db->get_PDI($pdi_id);
$pdi_catalog = $db->get_PDI_Catalog($pdi_id);
$stigs = $db->get_STIG_By_PDI($pdi_id);
$gds = $db->get_GoldDisk_By_PDI($pdi_id);
$ias = $db->get_IA_Controls_By_PDI($pdi_id);
?>

<!doctype HTML>

<html>
  <body>
    <table>
      <tr>
        <td><?php print (is_a($stigs, 'stig') ? $stigs->get_ID() : null); ?></td>
        <td><?php foreach ($gds as $key => $gd) : print $gd->get_ID() . " "; endforeach; ?></td>
        <td>Cat <?php print $pdi->get_Category_Level_String(); ?></td>
        <td><?php foreach ($ias as $key => $ia): print $ia->get_Type() . "-" . $ia->get_Type_ID() . " "; endforeach; ?></td>
        <td>PDI ID: <?php print $pdi->get_ID(); ?></td>
      </tr>
      <tr>
        <td colspan=5><span style="font-weight:bold;">Short Title:</span> <?php print nl2br($pdi->get_Short_Title()); ?></td>
      </tr>
      <tr>
        <td colspan=5><span style="font-weight:bold;">Description:</span><br /><?php print nl2br($pdi->get_Description()); ?></td>
      </tr>
      <tr>
        <td colspan=5><span style="font-weight:bold;">Check Contents:</span><br /><?php print nl2br($pdi->get_Check_Contents()); ?></td>
      </tr>
    </table>
  </body>
</html>