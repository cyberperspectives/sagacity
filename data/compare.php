<?php
/**
 * File: compare.php
 * Author: Ryan Prather
 * Purpose: Performs a high-level ST&E comparison
 * Created: Dec 9, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Dec 9, 2014 - File created
 */

include_once 'database.inc';
include_once 'header.inc';

$db = new db();

$left_ste = $db->get_STE($_REQUEST['left_ste'])[0];
$right_ste = $db->get_STE($_REQUEST['right_ste'])[0];

$left_tgts = $db->get_Target_Details($_REQUEST['left_ste']);
$right_tgts = $db->get_Target_Details($_REQUEST['right_ste']);

$left_cnt = (is_array($left_tgts) ? count($left_tgts) : 0);
$right_cnt = (is_array($right_tgts) ? count($right_tgts) : 0);

$left_cats = $db->get_STE_Category_List($left_ste->get_ID());
$right_cats = $db->get_STE_Category_List($right_ste->get_ID());

$left_cat_1 = 0;$left_cat_2 = 0;$left_cat_3 = 0;$left_nf = 0;$left_na = 0;$left_nr = 0;
$right_cat_1 = 0;$right_cat_2 = 0;$right_cat_3 = 0;$right_nf = 0;$right_na = 0;$right_nr = 0;

foreach($left_cats as $key => $cat) {
  $left_cat_1 += $db->get_Finding_Count_By_Status($cat->get_ID(), "Open", "1");
  $left_cat_2 += $db->get_Finding_Count_By_Status($cat->get_ID(), "Open", "2");
  $left_cat_3 += $db->get_Finding_Count_By_Status($cat->get_ID(), "Open", "3");
  $left_nf += $db->get_Finding_Count_By_Status($cat->get_ID(), "Not a Finding");
  $left_na += $db->get_Finding_Count_By_Status($cat->get_ID(), "Not Applicable");
  $left_nr += $db->get_Finding_Count_By_Status($cat->get_ID(), "Not Reviewed");
}

foreach($right_cats as $key => $cat) {
  $right_cat_1 += $db->get_Finding_Count_By_Status($cat->get_ID(), "Open", "1");
  $right_cat_2 += $db->get_Finding_Count_By_Status($cat->get_ID(), "Open", "2");
  $right_cat_3 += $db->get_Finding_Count_By_Status($cat->get_ID(), "Open", "3");
  $right_nf += $db->get_Finding_Count_By_Status($cat->get_ID(), "Not a Finding");
  $right_na += $db->get_Finding_Count_By_Status($cat->get_ID(), "Not Applicable");
  $right_nr += $db->get_Finding_Count_By_Status($cat->get_ID(), "Not Reviewed");
}

?>

<table style='width:600px;'>
  <tr>
    <th>ST&amp;E</th>
    <th>Target Count</th>
    <th class='cat_I'>I</th>
    <th class='cat_II'>II</th>
    <th class='cat_III'>III</th>
    <th class='nf'>NF</th>
    <th class='na'>NA</th>
    <th class='nr'>NR</th>
    <th>Charts?</th>
  </tr>
  <tr>
    <td><?php print $left_ste->get_System()->get_Name()." ".$left_ste->get_Site()->get_Name()." ".$left_ste->get_Eval_Start_Date()->format("Y-m-d")."-".$left_ste->get_Eval_End_Date()->format("Y-m-d") ?></td>
    <td><?php print $left_cnt; ?></td>
    <td class='cat_I'><?php print $left_cat_1; ?></td>
    <td class='cat_II'><?php print $left_cat_2; ?></td>
    <td class='cat_III'><?php print $left_cat_3; ?></td>
    <td class='nf'><?php print $left_nf; ?></td>
    <td class='na'><?php print $left_na; ?></td>
    <td class='nr'><?php print $left_nr; ?></td>
    <td>&nbsp;</td>
  </tr>
  <tr>
    <td><?php print $right_ste->get_System()->get_Name()." ".$right_ste->get_Site()->get_Name()." ".$right_ste->get_Eval_Start_Date()->format("Y-m-d")."-".$right_ste->get_Eval_End_Date()->format("Y-m-d") ?></td>
    <td><?php print $right_cnt; ?></td>
    <td class='cat_I'><?php print $right_cat_1; ?></td>
    <td class='cat_II'><?php print $right_cat_2; ?></td>
    <td class='cat_III'><?php print $right_cat_3; ?></td>
    <td class='nf'><?php print $right_nf; ?></td>
    <td class='na'><?php print $right_na; ?></td>
    <td class='nr'><?php print $right_nr; ?></td>
    <td>&nbsp;</td>
  </tr>
</table>
<form method="post" action="compare_targets.php">
  <input type="hidden" name="left_ste" value="<?php print $_REQUEST['left_ste']; ?>" />
  <input type="hidden" name="right_ste" value="<?php print $_REQUEST['right_ste']; ?>" />
  <input type="submit" name="action" value="Compare Targets" />
</form>
