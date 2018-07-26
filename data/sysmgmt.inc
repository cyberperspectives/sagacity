<?php
/**
 * File: sysmgmt.inc
 * Author: Ryan Prather
 * Purpose: For adding or editing systems
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
 *  - Sep 1, 2016 - Copyright updated and updated file purpose
 *  - May 19, 2017 - Migrated to filtering and changed save button to match buttons throughout
 *  - May 31, 2018 - Commented out CKEditor library
 */
$page = filter_input(INPUT_GET, 'p', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$sys_id = filter_input(INPUT_POST, 'system', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

?>

<style type="text/css">
    #description {
        width: 500px;
        height: 150px;
    }
</style>

<?php

if ($page == 'MSMgmt') {
  ?>

  <form method='post' action='?p=EditMS'>
    Select System:<br />
    <select name='system' onchange="this.form.submit();">
      <option value='0'>-- Please Select System --</option>
      <?php
      foreach ($all_systems as $key => $sys) :
        print $sys->get_Option();
      endforeach
      ;
      ?>
      <option value='0'>New...</option>
    </select>
  </form>

  <?php
}
elseif ($page == 'EditMS' && $sys_id) {
  $system = $db->get_System($sys_id);
  if (is_array($system) && count($system) && isset($system[0]) && is_a($system[0], 'system')) {
    $system = $system[0];
  }
  else {
    die("Couldn't find the selected system");
  }

  $mac = $system->get_MAC();
  $class = $system->get_Classification();
  $acred_type = $system->get_Accreditation_Type();
  ?>

  <script src='/script/ckeditor/ckeditor.js'></script>
  <script type='text/javascript'>
      $(function () {
          /*
        CKEDITOR.replace('description', {height: '100px', width: '950px', toolbar: [
            {name: 'document', items: ['Source']},
            {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
            {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
            {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
          ]});
          */
      });
  </script>

  <form method='post' action='?p=EditMS'>
    Select System:<br />
    <select name='system' onchange="this.form.submit();">
      <option value='0'>-- Please Select System --</option>
      <?php
      foreach ($all_systems as $key => $sys) :
        $selected = $sys_id == $sys->get_ID() ? true : false;
        print $sys->get_Option($selected);
      endforeach
      ;
      ?>
      <option value='0'>New...</option>
    </select>
  </form>

  <form method='post' action='?p=MSMgmt'>
    <input type='hidden' name='action' value='save-system' />
    <input type='hidden' name='system' value='<?php print $system->get_ID(); ?>' />
    Name:
    <input type='text' name='name' id='name'
           value='<?php print $system->get_Name(); ?>' /><br />
    Abbr:
    <input type='text' name='abbr' id='abbr'
           value='<?php print $system->get_Abbreviation(); ?>' /><br />
    MAC:
    <select name='mac' id='mac'>
      <option value='0'>-- Select MAC --</option>
      <option value='1' <?php print ($mac == 1 ? " selected" : ""); ?>>Level 1</option>
      <option value='2' <?php print ($mac == 2 ? " selected" : ""); ?>>Level 2</option>
      <option value='3' <?php print ($mac == 3 ? " selected" : ""); ?>>Level 3</option>
    </select><br />
    Classification:
    <select name='class' id='class'>
      <option value='0'>-- Select Classification --</option>
      <option value='Public'
              <?php print ($class == 'Public' ? ' selected' : ''); ?>>Public</option>
      <option value='Sensitive'
              <?php print ($class == 'Sensitive' ? ' selected' : ''); ?>>Sensitive</option>
      <option value='Classified'
              <?php print ($class == 'Classified' ? ' selected' : ''); ?>>Classified</option>
    </select><br />
    Accreditation Type:
    <select name="accred_type" id="accred_type">
      <option value='0'>-- Select Accreditation --</option>
      <option value='diacap'
              <?php print ($acred_type == accrediation_types::DIACAP ? ' selected' : ''); ?>>DIACAP</option>
      <option value='rmf'
              <?php print ($acred_type == accrediation_types::RMF ? ' selected' : ''); ?>>RMF</option>
    </select><br />
    System Description:<br />
    <textarea name='description' id='description' cols='1' rows='1'><?php print $system->get_Description(); ?></textarea><br />
    <input type='button' class='button' name='action' value='Save System' onclick='this.form.submit();' />
  </form>

  <?php
}
elseif ($page == 'EditMS' && !$sys_id) {
  ?>

  <script src='/script/ckeditor/ckeditor.js'></script>
  <script type='text/javascript'>
      $(function () {
        CKEDITOR.replace('description', {height: '100px', width: '950px', toolbar: [
            {name: 'document', items: ['Source']},
            {name: 'editor', items: ['Cut', 'Copy', 'Paste', 'PasteText', 'PastFromWord', '-', 'Undo', 'Redo']},
            {name: 'basicstyles', groups: ['basicstyles', 'cleanup'], items: ['Bold', 'Italic', 'Underline', '-', 'RemoveFormat']},
            {name: 'paragraph', groups: ['list', 'indent', 'blocks', 'align'], items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock']}
          ]});
      });
  </script>

  <form method='post' action='?p=MSMgmt'>
    <input type='hidden' name='action' value='save-system' />
    Name:
    <input type='text' name='name' id='name' /><br />
    Abbr:
    <input type='text' name='abbr' id='abbr' /><br />
    MAC:
    <select name='mac' id='mac'>
      <option value='0'>-- Select MAC --</option>
      <option value='1'>Level 1</option>
      <option value='2'>Level 2</option>
      <option value='3'>Level 3</option>
    </select><br />
    Classification:
    <select name='class' id='class'>
      <option value='0'>-- Select Classification --</option>
      <option value='Public'>Public</option>
      <option value='Sensitive'>Sensitive</option>
      <option value='Classified'>Classified</option>
    </select><br />
    Accreditation Type:
    <select name="accred_type" id="accred_type">
      <option value='0'>-- Select Accreditation --</option>
      <option value='diacap'>DIACAP</option>
      <option value='rmf'>RMF</option>
    </select><br />
    System Description:<br />
    <textarea name='description' id='description' cols='1' rows='1'>[paste system description here]</textarea><br />
    <input type='button' class='button' name='action' value='Save System' onclick='this.form.submit();' />
  </form>

<?php
}
