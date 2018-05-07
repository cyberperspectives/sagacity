<?php
/**
 * File: interview.php
 * Author: Ryan Prather
 * Purpose: Category Interview page
 * Created: Aug 25, 2014
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
 *  - Aug 25, 2014 - File created
 *  - Sep 1, 2016 - Copyright and file purpose updated
 *  - Dec 27, 2017 - Formatting
 *  - Jan 2, 2018 - Fixed bug #351
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

$db = new db();

$cats = $db->get_Question_Categories();
$type = filter_input(INPUT_POST, 'type', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => "/Unix|Windows/", 'flag' => FILTER_NULL_ON_FAILURE]]);
$cat_id = (int) filter_input(INPUT_POST, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
if (!$cat_id) {
  $cat_id = (int) filter_input(INPUT_GET, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
}
$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);

if ($type) {
  $db->set_Questions($type, $cat_id);
}

if ($action) {
  $questions = $db->get_Questions($cat_id, $type);

  foreach ($questions as $key => $ques) {
    $ques->answer = isset($_REQUEST[$ques->key]);
    $db->set_QA($cat, $ques);
  }

  header("Location: /ste");
}

$title_prefix = "Category Interview";
include_once 'header.inc';
?>

<div id="wrapper">
  <div id="main-wrapper">
    <div class="12u" id="main-content" style="overflow:scroll;">
      <div class="5grid-layout 5grid" style="text-align:right;">
        <div class="row">
          <div class="12u">
            <div style="float:left;margin-top:6px;">
              <form method="post" action="interview.php">
                <?php
                if ($cat_id) {
                  print "<input type='hidden' name='cat' value='$cat_id' />";
                }
                else {
                  die("Lost access to the category");
                }
                ?>
                Type:
                <select name="type" style="width:300px;" id="type" onchange="this.form.submit();">
                  <option> -- Select Interview Type -- </option>
                  <?php
                  foreach ($cats as $key => $cat) {
                    print "<option" . ($type == $cat ? " selected='true'" : "") . ">$cat</option>";
                  }
                  ?>
                </select>
              </form>
            </div>
          </div>
        </div>

        <div style='margin-left:20%;'>
          <?php
          if ($type) {
            $questions = $db->get_Questions($cat_id, $type);
            if (is_array($questions) && count($questions)) {
              ?>
              <form method='post' action='interview.php' id='tableContainer'>
                <div style="text-align:left;">
                  <input type='submit' name='action' value='Save' />
                </div>
                <input type='hidden' name='cat' value='<?php print ($cat_id ? $cat_id : ""); ?>' />
                <input type='hidden' name='type' value='<?php print ($type ? $type : ""); ?>' />
                <table style='width:800px;text-align:left;'>
                  <thead>
                    <tr>
                      <th>Question</th>
                      <th>Answer</th>
                    </tr>
                  </thead>

                  <tbody>
                    <?php
                    $odd = true;
                    foreach ($questions as $key => $ques) {
                      $class = ($odd ? 'odd_row' : 'even_row');
                      $ques->question = preg_replace("/\t/", "<span style='width:20px;display:inline-block;'>&nbsp;</span>", $ques->question);
                      print "<tr class='$class'><td>" . nl2br($ques->question) . "</td><td><input type='checkbox' name='" . $ques->key . "'" . ($ques->answer ? " checked='true'" : '') . " value='1' /></td></tr>";
                      $odd = !$odd;
                    }
                    ?>
                  </tbody>
                </table>
              </form>
              <?php
            }
          }
          ?>
        </div>
      </div>
    </div>
  </div>
</div>

<?php
include_once 'footer.inc';
