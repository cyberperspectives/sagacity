<?php
/**
 * File: compare_targets.php
 * Author: Ryan Prather
 * Purpose: Compares two targets
 * Created: Dec 15, 2014
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
 *  - Dec 15, 2014 - File created
 *  - Sep 1, 2016 - Copyright updated and file purpose
 */

include_once 'database.inc';
include_once 'header.inc';

$db = new db();

$left_ste = $db->get_STE($_REQUEST['left_ste'])[0];
$right_ste = $db->get_STE($_REQUEST['right_ste'])[0];

$tgt_compare = $db->get_Target_Comparison($left_ste, $right_ste);
?>

<style type='text/css'>
.none {
  background-color: #808080;
}
.header {
  color: #000;
}
td, th {
  border: solid 1px black;
}
</style>

<div id="wrapper">
  <div id="main-wrapper">
    <div class="12u" id="main-content">
      <div class="5grid-layout" style="text-align: right;">
        <div class="row">
          <div class="12u">

<table style='width:600px;'>
  <thead>
    <tr>
      <th class='header'>Target</th>
      <th class='cat_I'>I</th>
      <th class='cat_II'>II</th>
      <th class='cat_III'>III</th>
      <th class='nf'>NF</th>
      <th class='na'>NA</th>
      <th class='nr'>NR</th>
      <th class='none'>&nbsp;</th>
      <th class='cat_I'>I</th>
      <th class='cat_II'>II</th>
      <th class='cat_III'>III</th>
      <th class='nf'>NF</th>
      <th class='na'>NA</th>
      <th class='nr'>NR</th>
    </tr>
  </thead>

  <tbody>

<?php
$odd = true;
foreach($tgt_compare['left'] as $name => $left_tgt) {
?>
    <tr>
<?php
  if(is_null($left_tgt)) {
?>
      <td class="<?php print ($odd ? "odd" : "even"); ?>_row">
        <form method="post" action="compare_host.php">
          <input type='hidden' name='left_ste' value='<?php print $_REQUEST['left_ste']; ?>' />
          <input type='hidden' name='left_tgt' value='null' />
          <input type='hidden' name='right_ste' value='<?php print $_REQUEST['right_ste']; ?>' />
          <input type='hidden' name='right_tgt' value='<?php print $tgt_compare['right'][$name]->get_ID(); ?>' />
          <input type='submit' name='submit' value='<?php print $name; ?>' />
        </form>
      </td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
<?php
  }
  else {
?>
      <td class="<?php print ($odd ? "odd" : "even"); ?>_row">
        <form method="post" action="compare_host.php">
          <input type='hidden' name='left_ste' value='<?php print $_REQUEST['left_ste']; ?>' />
          <input type='hidden' name='left_tgt' value='<?php print $left_tgt->get_ID(); ?>' />
          <input type='hidden' name='right_ste' value='<?php print $_REQUEST['right_ste']; ?>' />
          <input type='hidden' name='right_tgt' value='<?php print isset($tgt_compare['right'][$name]) ? $tgt_compare['right'][$name]->get_ID() : 'null'; ?>' />
          <input type='submit' name='submit' value='<?php print $name; ?>' />
        </form>
      </td>
      <td class='cat_I'><?php print $db->get_Host_Finding_Count_By_Status($left_tgt, "Open", 1); ?></td>
      <td class='cat_II'><?php print $db->get_Host_Finding_Count_By_Status($left_tgt, "Open", 2); ?></td>
      <td class='cat_III'><?php print $db->get_Host_Finding_Count_By_Status($left_tgt, "Open", 3); ?></td>
      <td class='nf'><?php print $db->get_Host_Finding_Count_By_Status($left_tgt, "Not a Finding"); ?></td>
      <td class='na'><?php print $db->get_Host_Finding_Count_By_Status($left_tgt, "Not Applicable"); ?></td>
      <td class='nr'><?php print $db->get_Host_Finding_Count_By_Status($left_tgt, "Not Reviewed") ;?></td>
      <td class='none'>&nbsp;</td>
<?php
  }

  if(!isset($tgt_compare['right'][$name])) {
?>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
      <td class='none'>&nbsp;</td>
<?php
  }
  else {
?>
      <td class='cat_I'><?php print $db->get_Host_Finding_Count_By_Status($tgt_compare['right'][$name], "Open", 1); ?></td>
      <td class='cat_II'><?php print $db->get_Host_Finding_Count_By_Status($tgt_compare['right'][$name], "Open", 2); ?></td>
      <td class='cat_III'><?php print $db->get_Host_Finding_Count_By_Status($tgt_compare['right'][$name], "Open", 3); ?></td>
      <td class='nf'><?php print $db->get_Host_Finding_Count_By_Status($tgt_compare['right'][$name], "Not a Finding"); ?></td>
      <td class='na'><?php print $db->get_Host_Finding_Count_By_Status($tgt_compare['right'][$name], "Not Applicable"); ?></td>
      <td class='nr'><?php print $db->get_Host_Finding_Count_By_Status($tgt_compare['right'][$name], "Not Reviewed") ;?></td>
<?php
  }
?>
    </tr>
<?php
  $odd = !$odd;
}
?>

  </tbody>
</table>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
