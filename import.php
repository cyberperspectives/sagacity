<?php
/**
 * File: import.php
 * Author: Ryan.Prather
 * Purpose: Standardized import functionality
 * Created: Sep 27, 2013
 *
 * Change Log:
 *  - Sep 27, 2013 - File created
 *  - Aug 30, 2016 - Fixed progress bar
 *  - Mar 20, 2017 - Replaced with JS Dropzone library
 *  - Apr 7, 2017 - Added .xlsx extension to accepted files
 *  - May 13, 2017 - Made this more self-sustaining
 *  - May 19, 2017 - Change button to match others
 */
?>

<div id="import" class="box">
  <script type="text/javascript" src="/script/dropzone/dropzone.min.js"></script>
  <link type="text/css" href="/script/dropzone/dropzone.min.css" rel="stylesheet" />
  <link type="text/css" href="/script/dropzone/basic.min.css" rel="stylesheet" />

  <script type="text/javascript">
    Dropzone.options.dropzone = {
      maxFilesize: 150,
      success: function (file, res) {
        res = JSON.parse(res);
        if (res.imageUrl) {
          this.emit('thumbnail', file, res.imageUrl);
        }
      },
      acceptedFiles: "text/csv,text/plain,application/vnd.ms-excel,.nessus,.xml,.nmap,.ckl,.xlsx",
      addRemoveLinks: true,
      dictCancelUpload: "Cancel Upload",
      dictCancelUploadConfirmation: "Are you sure you want to cancel this upload?",
      dictRemoveFile: "Delete File?"
    };
    Dropzone.prototype.submitRequest = function (xhr, formData, files) {
      var dt = new Date(files[0].lastModifiedDate);
      xhr.setRequestHeader('X-FILENAME', files[0].name);
      xhr.setRequestHeader('X-FILEMTIME', dt.toISOString());
      return xhr.send(formData);
    };
    Dropzone.autoDiscover = false;

    $(function () {
      var mydz = new Dropzone('#dropzone');

      mydz.on('removedfile', function (file) {
        $.ajax('/ajax.php', {
          data: {
            action: 'delete-file',
            filename: file.name
          },
          success: function (data) {
            if (data.error) {

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
      });
    });

    /**
     * Function to import all the scans
     *
     * @returns {undefined}
     */
    function add_scans() {
      $.ajax('/ajax.php', {
        data: {
          action: 'add_scans',
          ste: '<?php print (isset($ste) && is_numeric($ste) ? $ste : ''); ?>',
          ignore: ($('#ignore_hidden').is(':checked') ? '1' : '0'),
          location: $('#location').val()
        },
        beforeSend: function () {
          close_box();
        },
        success: function (data) {
          if ($('#toggle_refresh').html() == 'Stop Refresh' && !to) {
            to = setTimeout(update_script_status, 3000);
          }
        },
        error: function (xhr, status, error) {
          console.error(error);
        },
        //timeout: 10000,
        dataType: 'json',
        method: 'post'
      });
    }
  </script>

  <form class="dropzone" action="/upload.php" id="dropzone">
    <div class="fallback">
      <input type="file" name="file" multiple />
    </div>
  </form>

  <div style='margin-left: 20px;'>
    <input type='text' id='location' placeholder='Physical Location...' /><br />
    <input type='button' class='button' id='add-scan' value='Add Scan Result' onclick='add_scans();' /><br />
    <label for='ignore_hidden' id='ignore_label'>Ignore Hidden Tabs in Excel eChecklists</label>
    <input type='checkbox' name='ignore_hidden' id='ignore_hidden' value='1' checked />
  </div>
</div>
