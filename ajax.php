<?php
/**
 * File: ajax.php
 * Author: Ryan Prather
 * Purpose: For AJAX queries from the UI
 * Created: Mar 9, 2015
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
 *  - Mar 9, 2015 - File created
 *  - Sep 1, 2016 - Updated Copyright and mass conversion of old PERL CGI script to PHP
 *  - Oct 10, 2016 - Converted target_filter function to output JSON instead of XML
 *  - Oct 24, 2016 - Converted update_script_status and get_hosts function to output JSON instead of XML
 * 					 Added add_scan action to start /exec/background_results.php script in background
 *  - Nov 7, 2016 - Moved a couple lines around for readability
 *  - Dec 7, 2016 - Fixed bug in update_script_status function that retrieved all scans even if a filter was turned on
 *  - Jan 30, 2017 - Formatting, added auto-categorization, and category deletion
 *  - Fed 15, 2017 - Formatting
 *  - Mar 4, 2017 - Moved from /cgi-bin to /
 *  - Mar 20, 2017 - Added functionality to delete result file after uploading.
 *  - Apr 5, 2017 - Fixed error in get_category_details
 *  - Apr 7, 2017 - Fixed errors in get_hosts with scan missing icons
 *  - May 13, 2017 - Added export-ckl.php threading from category header or target details page
 *                   Generate message when target searching yields no results
 *                   Added functionality for user to add or remove software from checklist and edit checklist specifics
 *  - May 19, 2017 - Added delete-host functionality for STE Ops page
 *  - May 20, 2017 - Added source icon to more quickly identify sources and change start time format
 *  - May 22, 2017 - Fixed update_script_status method to account for DataTables library
 *  - May 25, 2017 - Remove search method in favor of creating /search.php file to perform all search functions
 *  - Sep 28, 2017 - Fixed export-ckl to work on Windows system, removing single quotes from commandline strings - jao
 *  - Dec 27, 2017 - Merged database schemas into a single schema, also syntax updates
 *  - Jan 10, 2018 - Formatting and added calls for /ste/stats.php
 *  - Jan 15, 2018 - Updated to get formatted target notes
 *  - Jan 16, 2018 - Added ajax to auto update the cpe, cve, stig, and nasl loading progress.
  Moved scan deletion here
 */
set_time_limit(0);

include_once 'config.inc';
include_once 'import.inc';
include_once 'helper.inc';

chdir(DOC_ROOT);

$db   = new db();
$conn = new mysqli(DB_SERVER, "web", db::decrypt_pwd(), 'sagacity');

$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING);
$ste    = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT);
if (!$ste) {
    $ste = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT);
}

if (!$action) {
    die();
}

if ($action == 'update_notes') {
    print update_tgt_notes();
}
elseif ($action == 'search') {
    print search();
}
elseif ($action == 'chk_filter') {
    print header(JSON) . chk_filter();
}
elseif ($action == 'sw_filter') {
    print sw_filter();
}
elseif ($action == 'os_filter') {
    print sw_filter(true);
}
elseif ($action == 'update_proc_status') {
    print update_proc_status();
}
elseif ($action == 'update_proc_notes') {
    print update_proc_notes();
}
elseif ($action == 'update_script_status') {
    print update_script_status();
}
elseif ($action == 'update_finding_status') {
    print "<root>" . update_finding_status() . "</root>";
}
elseif ($action == 'update_finding_ia_controls') {
    print "<root>" . update_finding_ia_controls() . "</root>";
}
elseif ($action == 'update_finding_notes') {
    print "<root>" . update_finding_notes() . "</root>";
}
elseif ($action == 'update_risk_status') {
    print update_risk_status();
}
elseif ($action == 'update_risk_analysis') {
    print update_risk_analysis();
}
elseif ($action == 'update_control_completion') {
    print update_control_completion();
}
elseif ($action == 'update_stig_control') {
    print update_stig_control();
}
elseif ($action == 'refresh_counts') {
    print "<root>" . refresh_counts() . "</root>";
}
elseif ($action == 'get_control_details') {
    if ($_REQUEST['id'] == 'overall') {
        print get_STE_details();
    }
    else {
        print get_control_details();
    }
}
elseif ($action == 'update_STE') {
    print update_STE_details();
}
elseif ($action == 'update_STE_risk') {
    $conn->real_query(
        "UPDATE `sagacity`.`ste` SET `risk_status`='" .
        strtolower($conn->real_escape_string($_REQUEST['status'])) .
        "' WHERE `id`=" . $conn->real_escape_string($ste));
}
elseif ($action == 'get_hosts') {
    $cat_id = filter_input(INPUT_POST, 'cat_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    if (is_numeric($cat_id)) {
        print get_hosts($cat_id);
    }
    else {
        print json_encode(['error' => 'Invalid category ID']);
    }
}
elseif ($action == 'new-get-hosts') {
    $cat_id = filter_input(INPUT_POST, 'cat-id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    if (is_numeric($cat_id)) {
        print new_get_hosts($cat_id);
    }
    else {
        print json_encode(['error' => 'Invalid category ID']);
    }
}
elseif ($action == 'get_target_data') {
    print get_target_data($_REQUEST['type']);
}
elseif ($action == 'save_filter') {
    print $db->save_Filter($_REQUEST['type'], $_REQUEST['name'], $_REQUEST['criteria']);
}
elseif ($action == 'target-filter') {
    print header(JSON) . target_filter($ste, $_REQUEST['criteria']);
}
elseif ($action == 'scan-filter') {
    print scan_filter($ste, $_REQUEST['criteria']);
}
elseif ($action == 'finding-filter') {
    print finding_filter($ste, $_REQUEST['criteria']);
}
elseif ($action == 'reference-filter') {
    print reference_filter($ste, $_REQUEST['criteria']);
}
elseif ($action == 'get-saved-filter') {
    print get_saved_filter($_REQUEST['type'], $_REQUEST['name']);
}
elseif ($action == 'update-target-field') {
    print update_target_field($_REQUEST['field'], $_REQUEST['data']);
}
elseif ($action == 'get_category_details') {
    $cat_id = filter_input(INPUT_POST, 'cat_id', FILTER_VALIDATE_INT);
    print header(JSON) . get_category_details($cat_id);
}
elseif ($action == 'add_scans') {
    $import = new import();
    $import->scan_Result_Files(false);

    print header(JSON) . json_encode(array(
            'success' => 'Thread running'
    ));
}
elseif ($action == 'auto-categorize') {
    $db->auto_Catorgize_Targets($ste);

    print header(JSON) . json_encode(['success' => 'Categorized Targets'
    ]);
}
elseif ($action == 'delete-cat') {
    $cat_id = filter_input(INPUT_POST, 'cat_id', FILTER_VALIDATE_INT);
    if ($db->delete_Cat($cat_id)) {
        print header(JSON) . json_encode([
                'success' => 'Successfully deleted category'
        ]);
    }
}
elseif ($action == 'delete-file') {
    $file = TMP . "/" . filter_input(INPUT_POST, 'filename', FILTER_SANITIZE_STRING);
    if (file_exists($file)) {
        if (unlink($file)) {
            print header(JSON) . json_encode([
                    'success' => 'Deleted file'
            ]);
        }
        else {
            print header(JSON) . json_encode([
                    'error' => "Failed to delete $file"
            ]);
        }
    }
    else {
        print header(JSON) . json_encode([
                'error' => "$file does not exist"
        ]);
    }
}
elseif ($action == 'get-cat-data') {
    $fname     = filter_input(INPUT_POST, 'fname', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    $checklist = $db->get_Checklist_By_File($fname);

    if (isset($checklist[0])) {
        $checklist[0]->type = ucfirst($checklist[0]->type);
        print header(JSON) . json_encode($checklist[0]);
    }
    else {
        print header(JSON) . json_encode(array('error' => 'Error finding checklist'));
    }
}
elseif ($action == 'checklist-remove-software') {
    $chk_id = filter_input(INPUT_POST, 'chk_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $sw_id  = filter_input(INPUT_POST, 'sw_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

    $db->help->delete("sagacity.checklist_software_lookup", null, array(
        array(
            'field' => 'chk_id',
            'op'    => '=',
            'value' => $chk_id
        ),
        array(
            'field'  => 'sw_id',
            'op'     => '=',
            'value'  => $sw_id,
            'sql_op' => 'AND'
        )
    ));

    if ($db->help->execute()) {
        print header(JSON) . json_encode(array('success' => 'Relationship deleted'));
    }
    else {
        print header(JSON) . json_encode(array('error' => 'Failed to delete relationship'));
    }
}
elseif ($action == 'checklist-add-software') {
    $sw_id  = filter_input(INPUT_POST, 'sw_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $chk_id = filter_input(INPUT_POST, 'chk_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

    $db->help->insert("checklist_software_lookup", array(
        'sw_id'  => $sw_id,
        'chk_id' => $chk_id
        ), true);

    if (!$db->help->execute()) {
        print header(JSON) . json_encode(array('status' => 'Error adding the software to the checklist'));
    }
    else {
        print header(JSON) . json_encode(array('status' => 'Successfully added the software'));
    }
}
elseif ($action == 'export-ckl') {
    $cat_id = filter_input(INPUT_POST, 'cat', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $tgt_id = filter_input(INPUT_POST, 'tgt', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $script = null;

    if (!is_numeric($ste)) {
        die;
    }

    if ($cat_id && is_numeric($cat_id)) {
        $script = (defined('PHP_BIN') ? realpath(PHP_BIN) : realpath(PHP)) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/export-ckl.php") . " --" .
            " -s=$ste" .
            " -c=$cat_id";
    }
    elseif ($tgt_id && is_numeric($tgt_id)) {
        $script = (defined('PHP_BIN') ? realpath(PHP_BIN) : realpath(PHP)) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/export-ckl.php") . " --" .
            " -s=$ste" .
            " -t=$tgt_id";
    }

    if (!is_null($script)) {
        if (strtolower(substr(PHP_OS, 0, 3)) == "win") {
            $shell                   = new COM("WScript.Shell");
            $shell->CurrentDirectory = DOC_ROOT . "/exec";
            $shell->run($script, 0, false);
        }
        elseif (strtolower(substr(PHP_OS, 0, 3)) == 'lin') {
            exec("cd " . realpath(DOC_ROOT . "/exec") . " && {$script} > /dev/null &");
        }
    }
}
elseif ($action == 'delete-host') {
    $sel_tgts = json_decode(html_entity_decode(filter_input(INPUT_POST, 'selected_tgts', FILTER_SANITIZE_STRING)));
    if (is_array($sel_tgts) && count($sel_tgts)) {
        foreach ($sel_tgts as $tgt_id) {
            if (!$db->delete_Target($tgt_id)) {
                print header(JSON) . json_encode(array('error' => "Failed to delete target ID $tgt_id"));
                break;
            }
        }
    }
    elseif (is_numeric($sel_tgts)) {
        if (!$db->delete_Target($sel_tgts)) {
            print header(JSON) . json_encode(array('error' => "Failed to delete target ID $sel_tgts"));
        }
    }

    print header(JSON) . json_encode(['success' => "Deleted all selected target(s)"]);
}
elseif ($action == 'get-target-notes') {
    $tgt_id = filter_input(INPUT_POST, 'tgt-id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    if (is_numeric($tgt_id) && $tgt_id > 0) {
        $db->help->select("target", ['notes'], [
            [
                'field' => 'id',
                'op'    => '=',
                'value' => $tgt_id
            ]
        ]);
        $row = $db->help->execute();
        if (is_array($row) && count($row) && isset($row['notes'])) {
            print header(JSON) . json_encode(['notes' => $row['notes']]);
        }
    }
}
elseif ($action == 'save-target-notes') {
    $tgt_id = filter_input(INPUT_POST, 'tgt-id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $notes  = filter_input(INPUT_POST, 'notes', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    if (is_numeric($tgt_id) && $tgt_id > 0) {
        $db->help->update("target", [
            'notes' => htmlentities($notes)
            ], [
            [
                'field' => 'id',
                'op'    => '=',
                'value' => $tgt_id
            ]
        ]);
        if ($db->help->execute()) {
            print header(JSON) . json_encode(['success' => 'Updated target notes']);
        }
        else {
            print header(JSON) . json_encode(['error' => $db->help->c->error]);
        }
    }
}
elseif ($action == 'get-load-status') {
    $set = $db->get_Settings([
        'cpe-dl-progress', 'cpe-progress',
        'cve-dl-progress', 'cve-progress',
        'stig-dl-progress', 'stig-progress',
        'nasl-dl-progress', 'nasl-progress'
    ]);
    print json_encode($set);
}
elseif ($action == 'delete-scan') {
    $scan_id  = filter_input(INPUT_POST, 'scan-id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $del_tgts = (bool) filter_input(INPUT_POST, 'delete-targets', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    if ($scan_id) {
        if ($db->delete_Scan($ste, $scan_id, $del_tgts)) {
            print json_encode(['success' => 'Deleted Scan']);
        }
        else {
            print json_encode(['error' => 'Error deleting scan']);
        }
    }
}

function update_tgt_notes()
{
    global $db;
    $notes = str_replace("&nbsp;", "", filter_input(INPUT_POST, 'notes', FILTER_SANITIZE_STRING));
    $tgt   = filter_input(INPUT_POST, 'tgt', FILTER_VALIDATE_INT);

    $db->help->update("sagacity.target", array(
        'notes' => $notes
        ), array(
        array(
            'field' => 'id',
            'op'    => '=',
            'value' => $tgt
        )
    ));

    if (!$db->help->execute()) {
        return "failure";
    }
    else {
        return "success";
    }
}

function chk_filter()
{
    global $db;
    $tgt_id   = filter_input(INPUT_POST, 'tgt_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $filter   = filter_input(INPUT_POST, 'filter', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    $hide_old = (boolean) filter_input(INPUT_POST, 'hide_old', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

    $ret = array();
    $db->help->create_table("c", true, $db->help->select("sagacity.checklist", null, array(), array(
            'order' => '`ver` DESC, CONVERT(`release`, DECIMAL(4,2)) DESC'
    )));
    if (!$db->help->execute()) {
        return $ret;
    }
    $where = array();
    $flags = array();

    if (!empty($filter)) {
        $where = array(
            array(
                'field' => 'c.name',
                'op'    => LIKE,
                'value' => "'%{$filter}%'"
            )
        );
    }

    if (!empty($tgt_id)) {
        $where[]              = array(
            'field'  => 'tc.chk_id',
            'op'     => IS,
            'value'  => null,
            'sql_op' => 'AND'
        );
        $flags['table_joins'] = array(
            "LEFT JOIN sagacity.target_checklist tc ON tc.chk_id = c.id AND tc.tgt_id = $tgt_id"
        );
        $flags['order']       = 'c.name';
    }
    if ($hide_old) {
        $flags['group'] = 'c.name, c.type, c.id';
    }

    $db->help->select("c", array('c.id'), $where, $flags);

    $rows = $db->help->execute();
    if (is_array($rows) && count($rows) && isset($rows['id'])) {
        $rows = array(0 => $rows);
    }

    if (is_array($rows) && count($rows) && isset($rows[0])) {
        foreach ($rows as $row) {
            $chk = $db->get_Checklist($row['id']);
            if (is_array($chk) && count($chk) && isset($chk[0]) && is_a($chk[0], 'checklist')) {
                $ret[] = $chk[0];
            }
        }
    }

    return json_encode($ret);
}

function sw_filter($is_os = false)
{
    global $db;
    $ret    = [];
    $filter = "'%" . filter_input(INPUT_POST, 'filter', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE) . "%'";
    $tgt_id = filter_input(INPUT_POST, 'tgt_id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);

    $db->help->select("sagacity.software s", ['s.id', 's.cpe', 's.sw_string'], [
        [
            'field'      => 's.cpe',
            'op'         => LIKE,
            'value'      => $filter,
            'open-paren' => true
        ],
        [
            'field'  => 's.sw_string',
            'op'     => LIKE,
            'value'  => $filter,
            'sql_op' => 'OR'
        ],
        [
            'field'       => 's.short_sw_string',
            'op'          => LIKE,
            'value'       => $filter,
            'sql_op'      => 'OR',
            'close-paren' => true
        ],
        [
            'field'  => 'ts.sft_id',
            'op'     => IS,
            'value'  => null,
            'sql_op' => 'AND'
        ],
        [
            'field'  => 's.cpe',
            'op'     => LIKE,
            'value'  => ($is_os ? "'%/o%'" : "'%/a%'"),
            'sql_op' => 'AND'
        ]
        ], [
        'table_joins' => [
            "LEFT JOIN `sagacity`.`target_software` ts ON ts.`sft_id` = s.`id`" . ($tgt_id ? " AND ts.`tgt_id` = $tgt_id" : "")
        ],
        'order'       => 's.cpe',
        'limit'       => 25
    ]);

    $sw = $db->help->execute();

    if (is_array($sw) && count($sw) && isset($sw['id'])) {
        $sw = [0 => $sw];
    }

    if (is_array($sw) && count($sw) && isset($sw[0])) {
        foreach ($sw as $row) {
            $ret[] = [
                'sw_id'     => $row['id'],
                'cpe'       => $row['cpe'],
                'sw_string' => $row['sw_string']
            ];
        }
    }

    return header(JSON) . json_encode($ret);
}

function update_proc_status()
{
    global $conn, $ste;
    $control_id = str_replace("_", "-", substr(param('control'), 0, -7));
    if (preg_match("/[A-Z]{4}\-\d\-\d/", $control_id)) {
        $proc_id = $control_id;
        $sql     = "SELECT `ctrl_id` " .
            "FROM `sagacity`.`proc_findings` " .
            "WHERE " .
            "`ste_id`=" . $conn->real_escape_string($ste) . " AND " .
            "`proc_id`='" . $conn->real_escape_string($control_id) . "'";
        if ($res     = $conn->query($sql)) {
            if ($res->num_rows) {
                $row = $res->fetch_array(MYSQLI_ASSOC);

                $sql = "UPDATE `sagacity`.`proc_findings` " .
                    "SET `status`='" . $conn->real_escape_string($_REQUEST['status']) . " " .
                    "WHERE `ste_id`=" . $conn->real_escape_string($ste) . " AND " .
                    "`proc_id`='" . $conn->real_escape_string($row['ctrl_id']) . "'";
            }
            else {
                $sql = "INSERT INTO `sagacity`.`proc_findings` (`ste_id`,`ctrl_id`,`proc_id`,`status`) VALUES (" .
                    $_REQUEST['ste'] . "," .
                    "'" . $conn->real_escape_string(substr($proc_id, 0, 6)) . "'" .
                    "'" . $conn->real_escape_string($proc_id) . "'" .
                    "'" . $conn->real_escape_string($_REQUEST['status']) . "')";
            }

            if (!$conn->real_query($sql)) {
                error_log($conn->error);
                Sagacity_Error::sql_handler($sql);
            }
        }
    }
    else {
        $sql = "SELECT `sub_control_id` FROM `sagacity`.`proc_ia_sub_controls` WHERE `parent_control_id`=?";

        $sub_ctrls = db_helper::selectrow_array($conn, db_helper::mysql_escape_string($conn, $sql, $control_id));

        foreach ($sub_ctrl as $proc_id) {
            $sql = "SELECT COUNT(1) FROM `sagacity`.`proc_findings` WHERE `ste_id`=? AND `proc_id`=?";
            $sql = db_helper::mysql_escape_string($conn, $sql, $_REQUEST['ste'], $proc_id);
            list($cnt) = db_helper::selectrow_array($conn, $sql);
            if ($cnt) {
                db_helper::run($conn, "UPDATE `sagacity`.`proc_findings` SET `status`=? WHERE `ste_id`=? AND `proc_id`=?", $_REQUEST['status'], $_REQUEST['ste'], $proc_id);
            }
            else {
                db_helper::run($conn, "INSERT INTO `sagacity`.`proc_findings` (`ste_id`,`ctrl_id`,`proc_id`,`status`) VALUES (?,?,?,?)", $_REQUEST['ste'], $control_id, $proc_id, $_REQUEST['status']);
            }
        }
    }
}

function update_proc_notes()
{
    $control_id = $field      = $_REQUEST['control'];
    $match      = array();
    if (preg_match("/([A-Z]{4}\_\d\_\d)/", $control_id, $match)) {
        $control_id = str_replace("_", "-", $match[1]);

        $sql = "SELECT COUNT(1) FROM `sagacity`.`proc_findings` WHERE `ste_id`=? AND `proc_id`=?";

        switch ($field) {
            case (preg_match("/_test_result/", $field) ? true : false):
                $field = "`test_results`";
                break;
            case (preg_match("/_mit/", $field) ? true : false):
                $field = "`mitigations`";
                break;
            case (preg_match("/_milestone/", $field) ? true : false):
                $field = "`milestones`";
                break;
            case (preg_match("/_ref/", $field) ? true : false):
                $field = "`ref`";
                break;
            case (preg_match("/_notes/", $field) ? true : false):
                $field = "`notes`";
                break;
            default:
                $field = "";
        }

        list($cnt) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste'], $control_id);
        if ($cnt) {
            $sql = "UPDATE `sagacity`.`proc_findings` SET=? WHERE `ste_id`=? AND `proc_id`=?";

            db_helper::run($conn, $sql, $_REQUEST['notes'], $_REQUEST['ste'], $control_id);
        }
        else {
            $sql = "INSERT INTO `sagacity`.`proc_findings` (`ste_id`,`ctrl_id`,`proc_id`,`status`,$field) VALUES (?,?,?,?,?)";

            db_helper::run($conn, $sql, $_REQUEST['ste'], substr($control_id, 0, 6), $control_id, "Not Reviewed", $_REQUEST['notes']);
        }
    }
    elseif (preg_match("/([A-Z]{4}\_\d)/", $control_id, $match)) {
        $control_id = str_replace("_", "-", $match[1]);

        $sql = "SELECT COUNT(1) FROM `sagacity`.`control_findings` WHERE `ste_id`=? AND `control_id`=?";
        list($cnt) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste'], $control_id);

        switch ($field) {
            case (preg_match("/_vul_desc/", $field) ? true : false):
                $field = "`vul_desc`";
                break;
            case (preg_match("/_mit/", $field) ? true : false):
                $field = "`mitigations`";
                break;
            case (preg_match("/_ref/", $field) ? true : false):
                $field = "`ref`";
                break;
            case (preg_match("/_notes/", $field) ? true : false):
                $field = "`notes`";
                break;
            default:
                $field = "";
        }

        if ($cnt) {
            $sql = "UPDATE `sagacity`.`control_findings` SET $field=? WHERE `ste_id`=? AND `control_id`=?";

            db_helper::run($conn, $sql, $_REQUEST['notes'], $_REQUEST['ste'], $control_id);
        }
        else {
            $sql = "INSERT INTO `sagacity`.`control_findings` (`control_id`,`ste_id`,$field,`risk_status`) " .
                "VALUES (?,?,?,(SELECT LOWER(`impact`) FROM `sagacity`.`proc_ia_controls` WHERE `control_id`=?))";

            db_helper::run($conn, $sql, $control_id, $_REQUEST['ste'], $_REQUEST['notes'], $control_id);
        }
    }

    return true;
}

function refresh_counts()
{
    $ret = '';
    $sql = "SELECT `id`,`name` FROM `ste_cat` WHERE `ste_id`=?";

    $cats = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id']);

    foreach ($cats as $key => $cat) {
        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `sagacity`.`target` t " .
            "LEFT JOIN `target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "fs.`status`='Open' AND " .
            "f.`cat`=?) + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `checklist` c " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "fs.`status`='Open' AND " .
            "f.`cat`=?) AS 'sum_total'";

        list($open_cat_1) = db_helper::selectrow_array($conn, $sql2, $row['id'], '1', $row['id'], '1');
        list($open_cat_2) = db_helper::selectrow_array($conn, $sql2, $row['id'], '2', $row['id'], '2');
        list($open_cat_3) = db_helper::selectrow_array($conn, $sql2, $row['id'], '3', $row['id'], '3');

        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `target` t " .
            "LEFT JOIN `target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "(fs.`status`='Not Reviewed' OR fs.`status` IS NULL)) + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `checklist` c " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "(fs.`status`='Not Reviewed' OR fs.`status` IS NULL)) AS 'sum_total'";

        list($not_reviewed) = db_helper::selectrow_array($conn, $sql2, $row['id'], $row['id']);

        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `target` t " .
            "LEFT JOIN `target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "fs.`status`='Exception') + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `checklist` c " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "fs.`status`='Exception') AS 'sum_total'";

        list($exception) = db_helper::selectrow_array($conn, $sql2, $row['id'], $row['id']);

        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `target` t " .
            "LEFT JOIN `target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "fs.`status`='False Positive') + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `checklist` c " .
            "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "fs.`status`='False Positive') AS 'sum_total'";

        list($false_positive) = db_helper::selectrow_array($conn, $sql2, $row['id'], $row['id']);

        $row['name'] = str_replace(array(".", "-", " "), "", $row['name']);

        $ret .= "<cat name='" . $row['name'] . "' oc1='$open_cat_1' oc2='$open_cat_2' oc3='$open_cat_3' nr='$not_reviewed' ex='$exception' fp='$false_positive' />";
    }

    return $ret;
}

function update_finding_status()
{
    global $conn;
    $sql = "UPDATE `findings` SET " .
        "`findings_status_id`=? " .
        "WHERE " .
        "`tgt_id`=? AND `pdi_id`=?";

    db_helper::run($conn, $sql, $_REQUEST['status'], $_REQUEST['host_id'], $_REQUEST['pdi_id']);

    return true;
}

function update_finding_ia_controls()
{
    $controls = explode(" ", $_REQUEST['ia_controls']);
    $host_ids = explode(",", $_REQUEST['host_id']);

    return true;
}

function update_finding_notes()
{
    global $conn;
    $host_ids = explode(",", $_REQUEST['host_id']);

    $sql = "UPDATE `sagacity`.`findings` SET " .
        "`notes`=? " .
        "WHERE " .
        "`tgt_id` IN (" . implode(",", $host_ids) . ") AND `pdi_id`=?";

    db_helper::run($conn, $sql, $_REQUEST['notes'], $_REQUEST['pdi_id']);

    return true;
}

/**
 * Function to update the result script parsing status
 *
 * @global db $db
 * @global int $ste
 *
 * @return array
 */
function update_script_status()
{
    global $db, $ste;
    $ret = [];

    $type   = filter_input(INPUT_POST, 'type', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
    $status = filter_input(INPUT_POST, 'status', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);

    if (!empty($type) && !empty($status)) {
        $scans = $db->get_ScanData($ste, null, $status, $type);
    }
    elseif (!empty($type)) {
        $scans = $db->get_ScanData($ste, null, null, $type);
    }
    elseif (!empty($status)) {
        $scans = $db->get_ScanData($ste, null, $status);
    }
    else {
        $scans = $db->get_ScanData($ste);
    }

    foreach ($scans as $scan) {
        $file_name = str_replace(["(", ")"], "", str_replace(" ", "_", $scan->get_File_Name()));
        $diff      = $scan->get_Last_Update()->diff($scan->get_Start_Time());

        $ret[] = [
            "scan_id"    => $scan->get_ID(),
            "file_name"  => $scan->get_File_Name(),
            "id"         => $file_name,
            "file_date"  => $scan->get_File_DateTime()->format("Y-m-d"),
            "pid"        => $scan->get_PID(),
            "source"     => $scan->get_Source()->get_Name(),
            'source_img' => $scan->get_Source()->get_Icon(),
            "status"     => $scan->get_Status(),
            "perc_comp"  => $scan->get_Percentage_Complete(),
            "last_host"  => $scan->get_Last_Host(),
            "start_time" => $scan->get_Start_Time()->format("Y-m-d H:i:s"),
            "update"     => $scan->get_Last_Update()->format("Y-m-d H:i:s"),
            "host_count" => $scan->get_Total_Host_Count(),
            "run_time"   => $diff->format("%H:%I:%S")
        ];
    }

    return json_encode(['success' => 1, 'results' => $ret]);
}

/**
 *
 * @global mysqli $conn
 * @global db $db
 */
function get_STE_details()
{
    global $conn, $db;
    $ret        = '';
    $open_high  = $open_med   = $open_low   = $proc_na    = $proc_c     = $proc_total = $open_cat_1 = $open_cat_2 = $open_cat_3 = $tech_na    = $tech_nf    = $tech_total = 0;

    list($tech_total) = db_helper::selectrow_array($conn, "SELECT COUNT(1) FROM `sagacity`.`findings` f JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` WHERE t.`ste_id`=?", $_REQUEST['ste_id']);
    list($proc_total) = db_helper::selectrow_array($conn, "SELECT COUNT(1) FROM `sagacity`.`proc_findings` WHERE `ste_id`=?", $_REQUEST['ste_id']);

    $sql = "SELECT COUNT(1) " .
        "FROM `sagacity`.`proc_findings` pf " .
        "JOIN `sagacity`.`control_findings` cf ON pf.`ctrl_id`=cf.`control_id` " .
        "WHERE pf.`ste_id`=? " .
        "AND pf.`status`=? " .
        "AND cf.`risk_status`=? "
    ;

    list($open_high) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id'], 'Non-Compliant', 'high');
    list($open_med) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id'], 'Non-Compliant', 'medium');
    list($open_low) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id'], 'Non-Compliant', 'low');

    $sql = "SELECT COUNT(1) " .
        "FROM `sagacity`.`proc_findings` pf " .
        "JOIN `sagacity`.`control_findings` cf ON pf.`ctrl_id`=cf.`control_id` " .
        "WHERE pf.`ste_id`=? " .
        "AND pf.`status`=? "
    ;

    list($proc_na) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id'], 'Not Applicable');
    list($proc_c) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id'], 'Compliant');

    $sql = "SELECT `ste`.`deviations`,`ste`.`recommendations`,`ste`.`residual_risk`," .
        "`ste`.`conclusion`,`ste`.`risk_status`,sys.`mitigations`,sys.`executive_summary` " .
        "FROM `sagacity`.`ste`,`sagacity`.`system` sys " .
        "WHERE `ste`.`system_id`=sys.`id` AND " .
        "`ste`.`id`=?";

    list($dev, $rec, $res, $con, $status, $mit, $exec) = db_helper::selectrow_array($conn, $sql, $_REQUEST['ste_id']);

    $sql = "SELECT `id`,`name` FROM `sagacity`.`ste_cat` WHERE `ste_id`=?";

    $cats = $db->get_STE_Cat_List($_REQUEST['ste_id']);

    foreach ($cats as $cat) {
        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `sagacity`.`target` t " .
            "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "(fs.`status`='Open' OR fs.`status`='Exception') AND " .
            "f.`cat`=?) + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `sagacity`.`checklist` c " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "(fs.`status`='Open' OR fs.`status`='Exception') AND " .
            "f.`cat`=?) AS 'sum_total'";

        list($tmp) = db_helper::selectrow_array($conn, $sql2, $cat->get_ID(), '1', $cat->get_ID(), '1');
        $open_cat_1 += $tmp;
        list($tmp) = db_helper::selectrow_array($conn, $sql2, $cat->get_ID(), '2', $cat->get_ID(), '2');
        $open_cat_2 += $tmp;
        list($tmp) = db_helper::selectrow_array($conn, $sql2, $cat->get_ID(), '3', $cat->get_ID(), '3');
        $open_cat_3 += $tmp;

        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `sagacity`.`target` t " .
            "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "fs.`status`='Not Applicable') + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `sagacity`.`checklist` c " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "fs.`status`='Not Applicable') AS 'sum_total'";

        list($tmp) = db_helper::selectrow_array($conn, $sql2, $cat->get_ID(), $cat->get_ID());
        $tech_na += $tmp;

        $sql2 = "SELECT (SELECT COUNT(1) " .
            "FROM `sagacity`.`target` t " .
            "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` " .
            "WHERE t.`cat_id`=? AND " .
            "fs.`status`='Not a Finding') + " .
            "(SELECT COUNT(1) AS 'total' " .
            "FROM `sagacity`.`checklist` c " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` " .
            "JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` " .
            "WHERE t.`cat_id`=? AND " .
            "c.`name`='Orphan' AND " .
            "fs.`status`='Not a Finding') AS 'sum_total'";

        list($tmp) = db_helper::selectrow_array($conn, $sql2, $cat->get_ID(), $cat->get_ID());
        $tech_nf += $tmp;
    }

#'overall_mitigations,deviations,recommendations,residual_risk,conclusion,executive_summary'
    $ret .= "<div style='width:705px;float:left;'>" .
        "<p style='font-size:16px;font-weight:bolder;'>Overall Mitigations</p>" .
        "<textarea name='overall_mitigations' id='overall_mitigations' class='editor' cols='1' rows='1'>$mit</textarea>" .
        "<p style='font-size:16px;font-weight:bolder;'>Deviations</p>" .
        "<textarea name='deviations' id='deviations' class='editor' cols='1' rows='1'>$dev</textarea>" .
        "<p style='font-size:16px;font-weight:bolder;'>Recommendations</p>" .
        "<textarea name='recommendations' id='recommendations' class='editor' cols='1' rows='1'>$rec</textarea>" .
        "<span style='font-size:16px;font-weight:bolder;'>Residual Risk Analysis</span>&nbsp;&nbsp;" .
        "<select name='ste_risk' id='ste_risk' onchange='javascript:update_STE_risk(" . param('ste_id') . ");'>" .
        "<option" . ($status == 'low' ? ' selected' : '') . ">Low</option>" .
        "<option" . ($status == 'medium' ? ' selected' : '') . ">Medium</option>" .
        "<option" . ($status == 'high' ? ' selected' : '') . ">High</option>" .
        "</select><br />" .
        "<textarea name='residual_risk' id='residual_risk' class='editor' cols='1' rows='1'>$res</textarea>" .
        "<p style='font-size:16px;font-weight:bolder;'>Conclusion</p>" .
        "<textarea name='conclusion' id='conclusion' class='editor' cols='1' rows='1'>$con</textarea>" .
        "<p style='font-size:16px;font-weight:bolder;'>Executive Summary</p>" .
        "<textarea name='executive_summary' id='executive_summary' class='editor' cols='1' rows='1'>$exec</textarea>" .
        "</div>" .
        "<div style='width:290px;float:left;'>" .
        "<p style='font-size:16px;font-weight:bolder;'>Procedural ($proc_total)</p>" .
        "<table style='width:285px;' cellspacing='0' cellpadding='0'>" .
        "<tr>" .
        "<td class='high'>H</td>" .
        "<td class='medium'>M</td>" .
        "<td class='low'>L</td>" .
        "<td class='na'>NA</td>" .
        "<td class='c'>C</td>" .
        "</tr>" .
        "<tr>" .
        "<td class='high'>$open_high</td>" .
        "<td class='medium'>$open_med</td>" .
        "<td class='low'>$open_low</td>" .
        "<td class='na'>$proc_na</td>" .
        "<td class='c'>$proc_c</td>" .
        "</tr>" .
        "<tr>" .
        "<td class='high'>" . sprintf("%i%%", ($open_high / $proc_total) * 100) . "</td>" .
        "<td class='medium'>" . sprintf("%i%%", ($open_med / $proc_total) * 100) . "</td>" .
        "<td class='low'>" . sprintf("%i%%", ($open_low / $proc_total) * 100) . "</td>" .
        "<td class='na'>" . sprintf("%i%%", ($proc_na / $proc_total) * 100) . "</td>" .
        "<td class='c'>" . sprintf("%i%%", ($proc_c / $proc_total) * 100) . "</td>" .
        "</tr>" .
        "</table>" .
        "<p style='font-size:16px;font-weight:bolder;'>Technical ($tech_total)</p>" .
        "<table style='width:285px;' cellspacing='0' cellpadding='0'>" .
        "<tr>" .
        "<td class='high'>I</td>" .
        "<td class='medium'>II</td>" .
        "<td class='low'>III</td>" .
        "<td class='na'>NA</td>" .
        "<td class='c'>NF</td>" .
        "</tr>" .
        "<tr>" .
        "<td class='high'>$open_cat_1</td>" .
        "<td class='medium'>$open_cat_2</td>" .
        "<td class='low'>$open_cat_3</td>" .
        "<td class='na'>$tech_na</td>" .
        "<td class='c'>$tech_nf</td>" .
        "</tr>" .
        "<tr>" .
        "<td class='high'>" . sprintf("%i%%", ($open_cat_1 / $tech_total) * 100) . "</td>" .
        "<td class='medium'>" . sprintf("%i%%", ($open_cat_2 / $tech_total) * 100) . "</td>" .
        "<td class='low'>" . sprintf("%i%%", ($open_cat_3 / $tech_total) * 100) . "</td>" .
        "<td class='na'>" . sprintf("%i%%", ($tech_na / $tech_total) * 100) . "</td>" .
        "<td class='c'>" . sprintf("%i%%", ($tech_nf / $tech_total) * 100) . "</td>" .
        "</tr>" .
        "</table>" .
        "</div>";
}

function update_STE_details()
{
    global $conn;
    if ($_REQUEST['id'] == 'deviations') {
        $sql = "UPDATE `sagacity`.`ste` SET `deviations`=? WHERE `id`=?";
    }
    elseif ($_REQUEST['id'] == 'recommendations') {
        $sql = "UPDATE `sagacity`.`ste` SET `recommendations`=? WHERE `id`=?";
    }
    elseif ($_REQUEST['id'] == 'residual_risk') {
        $sql = "UPDATE `sagacity`.`ste` SET `residual_risk`=? WHERE `id`=?";
    }
    elseif ($_REQUEST['id'] == 'conclusion') {
        $sql = "UPDATE `sagacity`.`ste` SET `conclusion`=? WHERE `id`=?";
    }
    elseif ($_REQUEST['id'] == 'overall_mitigations') {
        $sql = "UPDATE `sagacity`.`system` JOIN `sagacity`.`ste` ON `ste`.`system_id`=`system`.`id` SET `mitigations`=? WHERE `ste`.`id`=?";
    }
    elseif ($_REQUEST['id'] == 'executive_summary') {
        $sql = "UPDATE `sagacity`.`system` JOIN `sagacity`.`ste` ON `ste`.`system_id`=`system`.`id` SET `executive_summary`=? WHERE `ste`.`id`=?";
    }

    db_helper::run($conn, $sql, $_REQUEST['text'], $_REQUEST['ste_id']);
}

function get_control_details()
{
    global $conn, $db;
    $ret = '';

    $sql = "SELECT " .
        "pc.`control_id`,pc.`name`,pc.`description`,pc.`impact`," .
        "cf.`vul_desc`,cf.`mitigations`,cf.`risk_analysis`,cf.`risk_status`,cf.`done` " .
        "FROM `sagacity`.`proc_ia_controls` pc " .
        "LEFT JOIN `sagacity`.`control_findings` cf ON cf.`control_id`=pc.`control_id` " .
        "WHERE pc.`control_id`=? AND cf.`ste_id`=?";

    $ste = $db->get_STE($_REQUEST['ste'])[0];

    $controls = $db->get_Proc_IA_Controls($ste, $_REQUEST['id'])[0];

    $risk_analysis = $controls->finding->risk_analysis;
    $ctrl_id       = $controls->get_Control_ID();
    $impact        = $controls->get_Impact();

    $ret .= "<div><span style='font-size:16pt;font-weight:bold;'>" .
        $controls->get_Control_ID() . " - " . $controls->get_Name() .
        "</span>" .
        "<span style='float:right;'>" .
        "<label for='done'>Done?</label> " .
        "<input type='checkbox' name='done'" . ($controls->finding->done ? " checked" : "") . " id='done' value='1' onclick='javascript:toggle_control_completion();' />" .
        "<input type='hidden' id='ctrl_id' value='" . $controls->get_Control_ID() . "' />" .
        "<span class='" . $controls->get_Worst_Status_String() . "' id='risk_status'>" .
        ucfirst($controls->get_Worst_Status_String()) .
        "</span>" .
        "</span>" .
        "</div>" .
        "<div class='description'>" . $controls->get_Description() . "</div>" .
        "<table style='border:solid 1px black;' id='procedures' class='tablesorter'>" .
        "<thead>" .
        "<tr>" .
        "<th style='width:200px;'>Procedure /<br />Validation Step</th>" .
        "<th style='width:400px;'>Findings</th>" .
        "<th style='width:600px;'>Mitigations</th>" .
        "</tr>" .
        "</thead>" .
        "<tbody>" .
        "<tr>" .
        "<td>" . $controls->get_Control_ID() . "<br />" . $controls->get_Name() . "</td>" .
        "<td>" . $controls->finding->vul_desc . "</td>" .
        "<td>" . $controls->finding->mitigations . "</td>" .
        "</tr>"
    ;

    $sql = "SELECT " .
        "psc.`sub_control_id`,psc.`name`,pf.`test_results`,pf.`mitigations`,pf.`status` " .
        "FROM `sagacity`.`proc_ia_sub_controls` psc " .
        "LEFT JOIN `sagacity`.`proc_findings` pf ON psc.`sub_control_id`=pf.`proc_id` " .
        "WHERE pf.`ste_id`=? AND " .
        "psc.`parent_control_id`=? AND " .
        "(pf.`status`='Non-Compliant' OR pf.`status`='Not Applicable')"
    ;

    if ($res = $conn->query($sql)) {
        while ($row = $res->fetch_array(MYSQLI_ASSOC)) {
            $status = str_replace(" ", "_", $row['status']);
            $ret    .= "<tr>" .
                "<td>" . $row['sub_control_id'] . "&nbsp;&nbsp;<span class='$status'>" . $row['status'] . "</span><br />" . $row['name'] . "</td>" .
                "<td>" . $row['test_results'] . "</td>" .
                "<td>" . $row['mitigations'] . "</td>" .
                "</tr>"
            ;
        }
    }

    $ret .= "</tbody></table>" .
        "<div>" .
        "<span style='font-size:16pt;font-weight:bold;'>" . $controls->get_Control_ID() . " - Risk Analysis&nbsp;&nbsp;" .
        "<select name='risk_analysis' onchange='javascript:update_risk_status(" . $_REQUEST['ste_id'] . ",\"" . $_REQUEST['id'] . "\",this.value);'>" .
        "<option" . ($impact == 'low' ? " selected" : "") . ">Low</option>" .
        "<option" . ($impact == 'medium' ? " selected" : "") . ">Medium</option>" .
        "<option" . ($impact == 'high' ? " selected" : "") . ">High</option>" .
        "</select>" .
        "</span>" .
        "<textarea id='analysis'>$risk_analysis</textarea>" .
        "</div>" .
        "<div>" .
        "<span style='font-size:16pt;font-weight:bold;'>$ctrl_id - Technical Findings</span>" .
        "<table id='stats'>" .
        "<tr>" .
        "<td style='color:white;background-color:red;'>I</td>" .
        "<td style='background-color:orange;'>II</td>" .
        "<td style='background-color:yellow;'>III</td>" .
        "<td style='background-color:#8db4e2;'>NA</td>" .
        "<td style='background-color:#92d050;'>NF</td>" .
        "<td>Unique</td>" .
        "<td>Hosts</td>" .
        "<td>Total</td>" .
        "</tr>";

    $cat_1 = $db->get_Control_Finding_Count($controls, $_REQUEST['ste_id'], "Open", 1);
    $cat_2 = $db->get_Control_Finding_Count($controls, $_REQUEST['ste_id'], "Open", 2);
    $cat_3 = $db->get_Control_Finding_Count($controls, $_REQUEST['ste_id'], "Open", 3);

    /*
      $sql = "SELECT ".
      "IFNULL((SELECT COUNT(1) ".
      "FROM `sagacity`.`target` t ".
      "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` ".
      "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` ".
      "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` ".
      "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` ".
      "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` ".
      "WHERE ".
      "(fs.`status`='Open' OR fs.`status`='Exception') AND ".
      "f.`cat`=? AND ".
      "fc.`ia_control`=? AND ".
      "t.`ste_id`=? ".
      "GROUP BY f.`pdi_id`".
      "), 0)".
      " + ".
      "IFNULL((SELECT COUNT(1) ".
      "FROM `sagacity`.`checklist` c ".
      "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` ".
      "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` ".
      "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` ".
      "LEFT JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` ".
      "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` ".
      "WHERE ".
      "c.`name`='Orphan' AND ".
      "(fs.`status`='Open' OR fs.`status`='Exception') AND ".
      "f.`cat`=? AND ".
      "fc.`ia_control`=? AND ".
      "t.`ste_id`=? ".
      "GROUP BY f.`pdi_id`".
      "), 0) AS 'sum_count'";

      ($cat_1) = $dbh->selectrow_array($sql, undef, 1, param('id'), param('ste_id'), 1, param('id'), param('ste_id'));
      ($cat_2) = $dbh->selectrow_array($sql, undef, 2, param('id'), param('ste_id'), 2, param('id'), param('ste_id'));
      ($cat_3) = $dbh->selectrow_array($sql, undef, 3, param('id'), param('ste_id'), 3, param('id'), param('ste_id'));
     */
    $sql = "SELECT " .
        "IFNULL((SELECT COUNT(1) " .
        "FROM `sagacity`.`target` t " .
        "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` " .
        "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
        "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
        "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` " .
        "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` " .
        "WHERE " .
        "(fs.`status`='Open' OR fs.`status`='Exception') AND " .
        "fc.`ia_control`=? AND " .
        "t.`ste_id`=? " .
        "), 0)" .
        " + " .
        "IFNULL((SELECT COUNT(1) " .
        "FROM `sagacity`.`checklist` c " .
        "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
        "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
        "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` " .
        "LEFT JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` " .
        "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` " .
        "WHERE " .
        "c.`name`='Orphan' AND " .
        "(fs.`status`='Open' OR fs.`status`='Exception') AND " .
        "fc.`ia_control`=? AND " .
        "t.`ste_id`=? " .
        "), 0) AS 'sum_count'";

    $unique = db_helper::selectrow_array($conn, $sql, $controls->get_Control_ID(), $_REQUEST['ste_id'], $controls->get_Control_ID(), $_REQUEST['ste_id']);
    /*
      $sql = "SELECT ".
      "IFNULL((SELECT COUNT(1) ".
      "FROM `sagacity`.`target` t ".
      "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` ".
      "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` ".
      "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` ".
      "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` ".
      "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` ".
      "WHERE ".
      "fs.`status`=? AND ".
      "fc.`ia_control`=? AND ".
      "t.`ste_id`=? ".
      "GROUP BY f.`pdi_id`".
      "), 0)".
      " + ".
      "IFNULL((SELECT COUNT(1) ".
      "FROM `sagacity`.`checklist` c ".
      "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` ".
      "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` ".
      "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` ".
      "LEFT JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` ".
      "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` ".
      "WHERE ".
      "c.`name`='Orphan' AND ".
      "fs.`status`=? AND ".
      "fc.`ia_control`=? AND ".
      "t.`ste_id`=? ".
      "GROUP BY f.`pdi_id`".
      "), 0) AS 'sum_count'";

      ($na) = $dbh->selectrow_array($sql, undef, "Not Applicable", param('id'), param('ste_id'), "Not Applicable", param('id'), param('ste_id'));
      ($nf) = $dbh->selectrow_array($sql, undef, "Not a Finding", param('id'), param('ste_id'), "Not a Finding", param('id'), param('ste_id'));
     */
    $na     = $db->get_Control_Finding_Count($controls, $_REQUEST['ste_id'], "Not Applicable");
    $nf     = $db->get_Control_Finding_Count($controls, $_REQUEST['ste_id'], "Not a Finding");

    $sql = "SELECT " .
        "IFNULL((SELECT COUNT(1) " .
        "FROM `sagacity`.`target` t " .
        "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` " .
        "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=tc.`chk_id` " .
        "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
        "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` " .
        "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` " .
        "WHERE " .
        "(fs.`status`='Open' OR fs.`status`='Exception') AND " .
        "fc.`ia_control`=? AND " .
        "t.`ste_id`=? " .
        "GROUP BY f.`tgt_id`" .
        "), 0)" .
        " + " .
        "IFNULL((SELECT COUNT(1) " .
        "FROM `sagacity`.`checklist` c " .
        "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id`=c.`id` " .
        "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id`=pcl.`pdi_id` " .
        "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id`=fs.`id` " .
        "LEFT JOIN `sagacity`.`target` t ON t.`id`=f.`tgt_id` " .
        "LEFT JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` " .
        "WHERE " .
        "c.`name`='Orphan' AND " .
        "(fs.`status`='Open' OR fs.`status`='Exception') AND " .
        "fc.`ia_control`=? AND " .
        "t.`ste_id`=? " .
        "GROUP BY f.`tgt_id`" .
        "), 0) AS 'sum_count'";

    $host_count = db_helper::selectrow_array($conn, $sql, $controls->get_Control_ID(), $_REQUEST['ste_id'], $controls->get_Control_ID(), $_REQUEST['ste_id']);

    $ret .= "<tr>" .
        "<td>$cat_1</td>" .
        "<td>$cat_2</td>" .
        "<td>$cat_3</td>" .
        "<td>$na</td>" .
        "<td>$nf</td>" .
        "<td>" . $unique['sum_count'] . "</td>" .
        "<td>" . $host_count['sum_count'] . "</td>" .
        "<td>" . ($cat_1 + $cat_2 + $cat_3) . "</td>" .
        "</tr>";

    $ret .= "</table>" .
        "</div>" .
        "<div>" .
        "<table id='stig_list' class='tablesorter'>" .
        "<thead>" .
        "<tr>" .
        "<th>STIG ID</td>" .
        "<th>Cat</td>" .
        "<th>M</td>" .
        "<th>Vulnerability Title</td>" .
        "<th>Affected Hosts</td>" .
        "<th>Notes<br />(inc.)</td>" .
        "</tr>" .
        "</thead>" .
        "<tbody>"
    ;

    $sql = "SELECT " .
        "f.`pdi_id`,s.`stig_id`,f.`cat`,pdi.`short_title`," .
        "(SELECT GROUP_CONCAT(fc.`ia_control` SEPARATOR ' ') " .
        "FROM `sagacity`.`finding_controls` fc " .
        "WHERE " .
        "fc.`finding_id`=f.`id` " .
        ") AS ia_controls " .
        "FROM `sagacity`.`findings` f " .
        "JOIN `sagacity`.`findings_status` fs ON fs.`id`=f.`findings_status_id` " .
        "JOIN `sagacity`.`stigs` s ON s.`pdi_id`=f.`pdi_id` " .
        "JOIN `sagacity`.`pdi_catalog` pdi ON pdi.`id`=f.`pdi_id` " .
        "WHERE (fs.`status`='Open' OR fs.`status`='Exception') " .
        "GROUP BY f.`pdi_id` " .
        "HAVING ia_controls LIKE '%" . $_REQUEST['id'] . "%' " .
        "ORDER BY s.`stig_id`"
    ;

    if ($res = $conn->query($sql)) {
        while ($row = $res->fetch_assoc()) {
            $cat    = str_repeat("I", $row['cat']);
            $ias    = explode(" ", $row['ia_controls']);
            $ia_cnt = (is_array($ias) ? count($ias) : 0);
            $stig   = str_replace(".", "", $row['stig_id']);

            $sql2 = "SELECT " .
                "GROUP_CONCAT(DISTINCT f.`id` SEPARATOR ',') AS 'finding_ids'," .
                "GROUP_CONCAT(DISTINCT t.`name` SEPARATOR ', ') AS 'affected_hosts',f.`notes` " .
                "FROM `sagacity`.`target` t " .
                "JOIN `sagacity`.`findings` f ON f.`tgt_id`=t.`id` " .
                "JOIN `sagacity`.`finding_controls` fc ON fc.`finding_id`=f.`id` " .
                "WHERE t.`ste_id`=? AND f.`pdi_id`=?";

            $row   = db_helper::selectrow_array($conn, $sql2, $_REQUEST['ste_id'], $row['pdi_id'])[0];
            $ids   = $row['finding_ids'];
            $hosts = $row['affected_hosts'];
            $notes = $row['notes'];

            $ret .= "<tr>" .
                "<td style='width:75px;'>" . $row['stig_id'] . "</td>" .
                "<td style='width:30px;'>$cat</td>" .
                "<td style='width:30px;'>" .
                ($ia_cnt > 1 ? "<img src='/img/multiples.jpg' style='width:20px;' title='" . $row['ia_controls'] . "' onclick=\"\$('\#$stig\_control').toggle();\" />" : "") .
                "<select style='display:none;' id='$stig\_control' onchange=\"javascript:update_stig_control('$ids', this.value);\"><option/>";

            for ($x = 0; $x < $ia_cnt; $x++) {
                $ret .= "<option>" . $ias[$x] . "</option>";
            }

            $ret .= "</select>" .
                "</td>" .
                "<td style='width:250px;'>" . $row['short_title'] . "</td>" .
                "<td style='width:150px;'>$hosts</td>" .
                "<td>$notes</td>" .
                "</tr>";
        }
    }


    $ret .= "</tbody></table></div>";

    return $ret;
}

function update_risk_status()
{
    global $conn;
    $sql = "UPDATE `sagacity`.`control_findings` SET `risk_status`=? WHERE `ste_id`=? AND `control_id`=?";
    db_helper::run($conn, $sql, strtolower($_REQUEST['status']), $_REQUEST['ste_id'], $_REQUEST['ctrl_id']);
}

function update_risk_analysis()
{
    global $conn;
    $sql = "UPDATE `sagacity`.`control_findings` SET `risk_analysis`=? WHERE `control_id`=? AND `ste_id`=?";
    db_helper::run($conn, $sql, $_REQUEST['text'], $_REQUEST['ctrl_id'], $_REQUEST['ste_id']);
}

function update_control_completion()
{
    global $conn;
    $sql = "UPDATE `sagacity`.`control_findings` SET `done`=IF(`done`=1,0,1) WHERE `control_id`=? AND `ste_id`=?";
    db_helper::run($conn, $sql, $_REQUEST['ctrl_id'], $_REQUEST['ste_id']);
}

function update_stig_control()
{
    global $conn;
    $sql = "DELETE FROM `sagacity`.`finding_controls` WHERE `finding_id` IN (" . $_REQUEST['ids'] . ")";
    $conn->real_query($sql);

    $sql = "INSERT INTO `sagacity`.`finding_controls` (`finding_id`,`ia_control`) VALUES ";
    $ids = explode(",", $_REQUEST['ids']);
    for ($x = 0; $x < count($ids); $x++) {
        $sql .= "(" . $ids[$x] . ",'" . $_REQUEST['ctrl_id'] . "'),";
    }
    $sql = substr($sql, 0, -1);
    $conn->real_query($sql);
}

/**
 * Function to get targets from the category
 *
 * @global db $db
 *
 * @param int $cat_id
 *
 * @return type
 */
function get_hosts($cat_id = null)
{
    global $db;
    $ret    = ['cat_id' => $cat_id];
    $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $tgts   = [];

    if ($cat_id) {
        $ste_cat = $db->get_Category($cat_id)[0];
        $tgts    = $db->get_Target_By_Category($cat_id);
    }
    elseif (is_numeric($ste_id)) {
        $tgts = $db->get_Unassigned_Targets($ste_id);
    }
    else {
        return json_encode(['error' => "Invalid info"]);
    }

    foreach ($tgts as $key => $tgt) {
        $chks = $db->get_Target_Checklists($tgt->get_ID());
        if ($cat_id) {
            $exp_scan_srcs = $db->get_Expected_Category_Sources($ste_cat);
        }
        else {
            $exp_scan_srcs = null;
        }
        $scan_srcs = $db->get_Target_Scan_Sources($tgt, $exp_scan_srcs);
        $icons     = [];
        $icon_str  = '';
        $src_str   = '';

        foreach ($chks as $chk) {
            if (!in_array($chk->get_Icon(), array_keys($icons))) {
                $icons[$chk->get_Icon()]['icon'] = $chk->get_Icon();
                $icons[$chk->get_Icon()]['name'] = '';
            }
            $icons[$chk->get_Icon()]['name'] .= "{$chk->get_Name()} V{$chk->get_Version()}R{$chk->get_Release()} ({$chk->get_type()})" . PHP_EOL;
        }

        foreach ($icons as $icon => $data) {
            $icon_str .= "<img src='/img/checklist_icons/$icon' title='{$data['name']}' class='checklist_image' />";
        }

        foreach ($scan_srcs as $key => $src) {
            $src_str .= "<img src='/img/scan_types/{$src['src']->get_Icon()}' title='{$src['src']->get_Name()}";
            if (isset($src['count']) && $src['count']) {
                $src_str .= " ({$src['count']})";
            }
            $src_str .= "' class='checklist_image' />";
        }

        $ret['targets'][] = array_merge([
            'id'       => $tgt->get_ID(),
            'ste_id'   => $tgt->get_STE_ID(),
            'name'     => $tgt->get_Name(),
            'os'       => $tgt->get_OS_String(),
            'location' => $tgt->get_Location(),
            'auto'     => $tgt->get_Task_Status($tgt->get_Auto_Status_ID()),
            'man'      => $tgt->get_Task_Status($tgt->get_Man_Status_ID()),
            'data'     => $tgt->get_Task_Status($tgt->get_Data_Status_ID()),
            'fp'       => $tgt->get_Task_Status($tgt->get_FP_Cat1_Status_ID()),
            'ip'       => (count($tgt->interfaces) ? array_keys($tgt->interfaces)[0] : ''),
            'notes'    => nl2br($tgt->get_Notes()),
            'scans'    => $src_str,
            'chk'      => $icon_str
        ]);
    }

    return json_encode($ret);
}

/**
 *
 * @global db $db
 * @param type $cat_id
 * @return type
 */
function new_get_hosts($cat_id)
{
    global $db;
    $ret    = ['cat_id' => $cat_id];
    $ste_id = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
    $tgts   = [];

    if ($cat_id) {
        $ste_cat = $db->get_Category($cat_id)[0];
        $tgts    = $db->get_Target_By_Category($cat_id);
    }
    elseif (is_numeric($ste_id)) {
        $tgts = $db->get_Unassigned_Targets($ste_id);
    }
    else {
        return json_encode(['error' => "Invalid info"]);
    }

    foreach ($tgts as $key => $tgt) {
        $chks = $db->get_Target_Checklists($tgt->get_ID());
        if ($cat_id) {
            $exp_scan_srcs = $db->get_Expected_Category_Sources($ste_cat);
        }
        else {
            $exp_scan_srcs = null;
        }
        $scan_srcs = $db->get_Target_Scan_Sources($tgt, $exp_scan_srcs);
        $icons     = [];
        $icon_str  = '';
        $src_str   = '';

        foreach ($chks as $chk) {
            if (!in_array($chk->get_Icon(), array_keys($icons))) {
                $icons[$chk->get_Icon()]['icon'] = $chk->get_Icon();
                $icons[$chk->get_Icon()]['name'] = '';
            }
            $icons[$chk->get_Icon()]['name'] .= "{$chk->get_Name()} V{$chk->get_Version()}R{$chk->get_Release()} ({$chk->get_type()})" . PHP_EOL;
        }

        foreach ($icons as $icon => $data) {
            $icon_str .= "<img src='/img/checklist_icons/$icon' title='{$data['name']}' class='checklist_image' />";
        }

        foreach ($scan_srcs as $key => $src) {
            $src_str .= "<img src='/img/scan_types/{$src['src']->get_Icon()}' title='{$src['src']->get_Name()}";
            if (isset($src['count']) && $src['count']) {
                $src_str .= " ({$src['count']})";
            }
            $src_str .= "' class='checklist_image' />";
        }

        $ret['targets'][] = array_merge([
            'id'       => $tgt->get_ID(),
            'ste_id'   => $tgt->get_STE_ID(),
            'name'     => $tgt->get_Name(),
            'os'       => $tgt->get_OS_String(),
            'location' => $tgt->get_Location(),
            'ip'       => (count($tgt->interfaces) ? array_keys($tgt->interfaces)[0] : ''),
            'notes'    => $tgt->getDisplayNotes(),
            'scans'    => $src_str,
            'chk'      => $icon_str,
            'nr'       => $tgt->getNotReviewedCount(),
            'na'       => $tgt->getNotApplicableCount(),
            'nf'       => $tgt->getNotAFindingCount(),
            'cat_1'    => $tgt->getCat1Count(),
            'cat_2'    => $tgt->getCat2Count(),
            'cat_3'    => $tgt->getCat3Count(),
            'comp'     => $tgt->getCompliantPercent(),
            'assessed' => $tgt->getAssessedPercent()
        ]);
    }

    return json_encode($ret);
}

function get_target_data()
{
    global $db;

    $tgt = $db->get_Target_Details($_REQUEST['ste_id'], $_REQUEST['tgt_id'])[0];

    switch ($_REQUEST['type']) {
        case 'netstat':
            return $tgt->get_Netstat_Connections();
        case 'routes':
            return $tgt->get_Routes();
        case 'firewall':
            return $tgt->get_Firewall_Config();
        case 'shares':
            return $tgt->get_Shares();
        case 'mounted':
            return $tgt->get_Mounted();
        case 'process_list':
            return $tgt->get_Process_List();
        case 'autorun':
            return $tgt->get_Autorun();
        case 'services':
            return $tgt->get_Services();
        case 'remote_registry':
            return $tgt->get_Remote_Registry();
        case 'system':
            return $tgt->get_System();
        case 'bios':
            return $tgt->get_BIOS();
        case 'copyright':
            return $tgt->get_Copyright();
        case 'missing_patches':
            return $tgt->get_Missing_Patches();
        case 'user_list':
            return $tgt->get_User_List();
        case 'disabled_accts':
            return $tgt->get_Disabled_Accts();
        case 'stag_pwds':
            return $tgt->get_Stag_Pwds();
        case 'never_logged_in':
            return $tgt->get_Never_Logged_In();
        case 'pwds_never_expire':
            return $tgt->get_Pwds_Never_Expire();
    }

    return null;
}

function target_filter($ste_id, $criteria)
{
    global $db, $conn;
    $where = array();
    $tgts  = array();
    $idx   = 0;
    $like  = false;
    $ret   = array();

    $search = explode("\n", $criteria);
    unset($search[count($search) - 1]);

    foreach ($search as $str) {
        if (!$str) {
            continue;
        }
        switch ($str) {
            case (preg_match("/name /i", $str) ? true : false):
                $where[] = "t.`name`";
                break;
            case (preg_match("/sw /i", $str) ? true : false):
                $where[] = "sw.`cpe`";
                break;
            case (preg_match("/os /i", $str) ? true : false):
                $where[] = "os.`cpe`";
                break;
            case (preg_match("/auto status /i", $str) ? true : false):
                $where[] = "`as`.`status`";
                break;
            case (preg_match("/manual status /i", $str) ? true : false):
                $where[] = "ms.`status`";
                break;
            case (preg_match("/data gathering status /i", $str) ? true : false):
                $where[] = "ds.`status`";
                break;
            case (preg_match("/fp\/cat i status /i", $str) ? true : false):
                $where[] = "fp.`status`";
                break;
            case (preg_match("/category /i", $str) ? true : false):
                $where[] = "t.`cat_id`";
                break;
            case (preg_match("/open port /i", $str) ? true : false):
                $where[] = "CONCAT(pps.`proto`,'/',pps.`port`)";
                break;
            default:
                continue 2;
        }

        if (($pos = strpos($str, "!~")) !== false) {
            $where[$idx] .= " NOT LIKE ";
            $like        = true;
        }
        elseif (($pos = strpos($str, "~=")) !== false) {
            $where[$idx] .= " LIKE ";
            $like        = true;
        }
        elseif (($pos = strpos($str, "!=")) !== false) {
            $where[$idx] .= " != ";
        }
        elseif (($pos = strpos($str, "=")) !== false) {
            $where[$idx] .= " = ";
            $pos--;
        }

        $where[$idx] .= "'" . ($like ? "%" : "") .
            $conn->real_escape_string(substr($str, $pos + 4, -1)) .
            ($like ? "%" : "") . "'";

        $idx++;
        $like = false;
    }

    $where_str = implode(" AND ", $where);

    $sql = "SELECT COUNT(DISTINCT(t.`id`)) as 'cnt' " .
        "FROM `sagacity`.`target` t " .
        "LEFT JOIN `sagacity`.`task_status` `as` ON t.`auto_status_id`=`as`.`id` " .
        "LEFT JOIN `sagacity`.`task_status` ms ON t.`man_status_id`=ms.`id` " .
        "LEFT JOIN `sagacity`.`task_status` ds ON t.`data_status_id`=ds.`id` " .
        "LEFT JOIN `sagacity`.`task_status` fp ON t.`fp_cat1_status_id`=fp.`id` " .
        "LEFT JOIN `sagacity`.`target_software` ts ON ts.`tgt_id`=t.`id` " .
        "LEFT JOIN `sagacity`.`software` sw ON ts.`sft_id`=sw.`id` " .
        "LEFT JOIN `sagacity`.`software` os ON t.`os_id`=os.`id` " .
        "LEFT JOIN `sagacity`.`interfaces` i ON t.`id`=i.`tgt_id` " .
        "LEFT JOIN `sagacity`.`pps_list` hp ON hp.`int_id`=i.`id` " .
        "LEFT JOIN `sagacity`.`ports_proto_services` pps ON pps.`id`=hp.`pps_id` " .
        "WHERE " .
        $where_str
    ;
    $cnt = 0;
    if ($res = $conn->query($sql)) {
        $cnt = $res->fetch_array()[0];
    }
    else {
        error_log($conn->error);
        Sagacity_Error::sql_handler($sql);
    }
    $ret['count'] = $cnt;

    $sql = "SELECT DISTINCT(t.`id`) " .
        "FROM `sagacity`.`target` t " .
        "LEFT JOIN `sagacity`.`task_status` `as` ON t.`auto_status_id`=`as`.`id` " .
        "LEFT JOIN `sagacity`.`task_status` ms ON t.`man_status_id`=ms.`id` " .
        "LEFT JOIN `sagacity`.`task_status` ds ON t.`data_status_id`=ds.`id` " .
        "LEFT JOIN `sagacity`.`task_status` fp ON t.`fp_cat1_status_id`=fp.`id` " .
        "LEFT JOIN `sagacity`.`target_software` ts ON ts.`tgt_id`=t.`id` " .
        "LEFT JOIN `sagacity`.`software` sw ON ts.`sft_id`=sw.`id` " .
        "LEFT JOIN `sagacity`.`software` os ON t.`os_id`=os.`id` " .
        "LEFT JOIN `sagacity`.`interfaces` i ON t.`id`=i.`tgt_id` " .
        "LEFT JOIN `sagacity`.`pps_list` hp ON hp.`int_id`=i.`id` " .
        "LEFT JOIN `sagacity`.`ports_proto_services` pps ON pps.`id`=hp.`pps_id` " .
        "WHERE " .
        $where_str . " " .
        ($_REQUEST['count'] != 'all' ? "LIMIT " . $_REQUEST['start_count'] . "," . $_REQUEST['count'] : "")
    ;

    if ($res = $conn->query($sql)) {
        while ($row = $res->fetch_assoc()) {
            $tgts[] = $db->get_Target_Details($_REQUEST['ste'], $row['id'])[0];
        }
    }
    else {
        error_log($conn->error);
        Sagacity_Error::sql_handler($sql);
    }

    foreach ($tgts as $tgt) {
        $cat_id  = $tgt->get_Cat_ID();
        $ste_cat = $db->get_Category($cat_id);
        $chks    = $db->get_Target_Checklists($tgt->get_ID());
        if (isset($cat_id)) {
            $exp_scan_srcs = $db->get_Expected_Category_Sources($ste_cat);
        }
        else {
            $exp_scan_srcs = null;
        }
        $scan_srcs = $db->get_Target_Scan_Sources($tgt, $exp_scan_srcs);
        $icons     = array();
        $icon_str  = '';
        $src_str   = '';

        foreach ($chks as $chk) {
            if (!in_array($chk->get_Icon(), array_keys($icons))) {
                $icons[$chk->get_Icon()]['icon'] = $chk->get_Icon();
                $icons[$chk->get_Icon()]['name'] = '';
            }
            $icons[$chk->get_Icon()]['name'] .= $chk->get_Name() . " V" . $chk->get_Version() . "R" . $chk->get_Release() . " (" . $chk->get_type() . ")" . PHP_EOL;
        }

        foreach ($icons as $icon => $data) {
            $icon_str .= "<img src='/img/checklist_icons/" . $icon . "' title='" . $data['name'] . "' class='checklist_image' />";
        }

        foreach ($scan_srcs as $src) {
            $src_str .= "<img src='/img/scan_types/" . $src['src']->get_Icon() . "' title='" . $src['src']->get_Name();
            if (isset($src['count']) && $src['count']) {
                $src_str .= " (" . $src['count'] . ")";
            }
            $src_str .= "' class='checklist_image' />";
        }

        $ret['targets'][] = array_merge($tgt->get_JSON(), array(
            'scans' => $src_str,
            'chk'   => $icon_str
        ));
    }

    if (isset($ret['targets']) && is_array($ret['targets']) && count($ret['targets'])) {
        return json_encode($ret);
    }
    else {
        return json_encode(array('count' => 0));
    }
}

function reference_filter($criteria)
{
    global $db, $conn;
    $where = array();
    $ref   = array();
    $idx   = 0;
    $ret   = '';
    $like  = false;
    $odd   = true;

    $sql = "SELECT * FROM `sagacity`.`pdi_catalog` pdi ";

    $query = array(
        'cce'  => array(
            'sql'   => "LEFT JOIN `sagacity`.`cce` ON cce.`pdi_id`=pdi.`id` ",
            'added' => false
        ),
        'cve'  => array(
            'sql'   => "LEFT JOIN `sagacity`.`cve` ON cve.`pdi_id`=pdi.`id` " .
            "LEFT JOIN `sagacity`.`cve_db` ON cve_db.`cve_id`=cve.`cve_id` " .
            "LEFT JOIN `sagacity`.`cve_references` ref ON ref.`cve_seq`=cve_db.`cve_id` " .
            "LEFT JOIN `sagacity`.`cve_web` web ON web.`cve_id`=cve_db.`cve_id` ",
            'added' => false,
        ),
        'vms'  => array(
            'sql'   => "LEFT JOIN `sagacity`.`golddisk` gd ON gd.`pdi_id`=pdi.`id` ",
            'added' => false,
        ),
        'iavm' => array(
            'sql'   => "LEFT JOIN `sagacity`.`iavm_notices` iavm ON iavm.`pdi_id`=pdi.`id` ",
            'added' => false,
        )
    );

    $xml  = new DOMDocument();
    $xml->appendChild($root = xml_helper($xml, "root"));

    $search = explode("\n", $criteria);
    unset($search[count($search) - 1]);

    foreach ($search as $str) {
        switch ($str) {
            case (preg_match("/cce /i", $str) ? true : false):
                if (!$query['cce']['added']) {
                    $sql .= $query['cce']['sql'];
                }
                $query['cce']['added'] = true;
                $where[]               = "";
                break;
            case (preg_match("/cpe /i", $str) ? true : false):
                $where[]               = "";
                break;
            case (preg_match("/cve /i", $str) ? true : false):
                if (!$query['cve']['added']) {
                    $sql .= $query['cve']['sql'];
                }
                $query['cve']['added'] = true;
                $where[]               = "";
                break;
            case (preg_match("/ia control /i", $str) ? true : false):
                $where[]               = "";
                break;
            case (preg_match("/iavm /i", $str) ? true : false):
                if (!$query['iavm']['added']) {
                    $sql .= $query['iavm']['sql'];
                }
                $query['iavm']['added'] = true;
                $where[]                = "";
                break;
            case (preg_match("/nessus plugin id /i", $str) ? true : false):
                $where[]                = "";
                break;
            case (preg_match("/oval /i", $str) ? true : false):
                $where[]                = "";
                break;
            case (preg_match("/reference /i", $str) ? true : false):
                $where[]                = "";
                break;
            case (preg_match("/stig id /i", $str) ? true : false):
                $where[]                = "";
                break;
            case (preg_match("/sv rule /i", $str) ? true : false):
                $where[]                = "";
                break;
            case (preg_match("/vms id /i", $str) ? true : false):
                if (!$query['vms']['added']) {
                    $sql .= $query['vms']['sql'];
                }
                $query['vms']['added'] = true;
                $where[]               = "";
                break;
            case (preg_match("/vendor advisory /i", $str) ? true : false):
                $where[]               = "";
                break;
            case (preg_match("/check contents /i", $str) ? true : false):
                $where[]               = "";
                break;
            case (preg_match("/short title /i", $str) ? true : false):
                $where[]               = "";
                break;
            case (preg_match("/description /i", $str) ? true : false):
                $where[]               = "";
                break;
            default:
                continue 2;
        }

        if (($pos = strpos($str, "!~")) !== false) {
            $where[$idx] .= " NOT LIKE ";
            $like        = true;
        }
        elseif (($pos = strpos($str, "~=")) !== false) {
            $where[$idx] .= " LIKE ";
            $like        = true;
        }
        elseif (($pos = strpos($str, "!=")) !== false) {
            $where[$idx] .= " != ";
        }
        elseif (($pos = strpos($str, "=")) !== false) {
            $where[$idx] .= " = ";
            $pos--;
        }

        $where[$idx] .= "'" . ($like ? "%" : "") .
            $conn->real_escape_string(substr($str, $pos + 4, -1)) .
            ($like ? "%" : "") . "'";

        $idx++;
        $like = false;
    }

    $where_str = implode(" AND ", $where);

    $sql = "SELECT COUNT(t.`id`) as 'cnt' " .
        "WHERE " .
        $where_str;

    $cnt = 0;
    if ($res = $conn->query($sql)) {
        $cnt = $res->fetch_array()[0];
    }
    else {
        error_log($conn->error);
        Sagacity_Error::sql_handler($sql);
    }
    $root->setAttribute('count', $cnt);

    $sql = "SELECT t.`id` " .
        " " .
        "WHERE " .
        $where_str . " " .
        ($_REQUEST['count'] != 'all' ? "LIMIT " . $_REQUEST['start_count'] . "," . $_REQUEST['count'] : "")
    ;

    if ($res = $conn->query($sql)) {
        while ($row = $res->fetch_assoc()) {

        }
    }
    else {
        error_log($conn->error);
        Sagacity_Error::sql_handler($sql);
    }

    return $xml->saveXML();
}

function scan_filter($ste_id, $criteria)
{

}

function finding_filter($ste_id, $criteria)
{

}

function get_saved_filter($type, $filter_name)
{
    global $db;
    $filter = $db->get_Filters($type, $filter_name);
    $ret    = array();

    if (is_array($filter) && count($filter)) {
        $filter = $filter[0];
        foreach (explode("\n", $filter['criteria']) as $cri) {
            if ($cri)
                $ret[] = $cri;
        }
    }

    return json_encode($ret);
}

function update_target_field($field, $data)
{
    global $db, $conn;

    $sql = "UPDATE `sagacity`.`target` t " .
        "LEFT JOIN `sagacity`.`target_software` ts ON t.`id`=ts.`tgt_id` " .
        "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id`=tc.`tgt_id` " .
        "LEFT JOIN `sagacity`.`target_net_meta` tnm ON t.`id`=tnm.`tgt_id` " .
        "LEFT JOIN `sagacity`.`target_sys_meta` tsm ON t.`id`=tsm.`tgt_id` " .
        "LEFT JOIN `sagacity`.`target_user_meta` tum ON t.`id`=tum.`tgt_id` " .
        "SET ";

    switch ($field) {
        case 'name':
            $sql .= "t.`name`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'location':
            $sql .= "t.`location`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'wmi_pid':
            $sql .= "tsm.`wmi_listening_pid`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'last_login':
            $sql .= "tum.`last_login`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'login':
            $sql .= "tum.`login`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'notes':
            $sql .= "t.`notes`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'auto_status':
            $sql .= "t.`auto_status_id`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'man_status':
            $sql .= "t.`man_status_id`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'data_status':
            $sql .= "t.`data_status_id`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'fp-cat1_status':
            $sql .= "t.`fp_cat1_status_id`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'vm':
            $sql .= "tsm.`is_vm`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'pp_on':
            $sql .= "t.`pp_off`=" . ($data == '1' ? '0' : '1');
            break;
        case 'netstat_data':
            $sql .= "tnm.`netstat_connections`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'routes_data':
            $sql .= "tnm.`routes`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'shares_data':
            $sql .= "tnm.`shares`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'firewall_data':
            $sql .= "tnm.`firewall_config`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'mounted_data':
            $sql .= "tsm.`mounted`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'process_list_data':
            $sql .= "tsm.`process_list`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'autorun_data':
            $sql .= "tsm.`autorun`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'services_data':
            $sql .= "tsm.`services`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'remote_registry_data':
            $sql .= "tsm.`remote_registry`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'copyright_data':
            $sql .= "tsm.`copyrighted`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'system_data':
            $sql .= "tsm.`system`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'bios_data':
            $sql .= "tsm.`bios`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'missing_patches_data':
            $sql .= "t.`missing_patches`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'user_list_data':
            $sql .= "tum.`user_list`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'disabled_accts_data':
            $sql .= "tum.`disabled_accts`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'stag_pwds_data':
            $sql .= "tum.`stag_pwds`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'never_logged_in_data':
            $sql .= "tum.`never_logged_in`='" . $conn->real_escape_string($data) . "'";
            break;
        case 'pwds_never_expire_data':
            $sql .= "tum.`pwd_never_expires`='" . $conn->real_escape_string($data) . "'";
            break;
        case '':
            $sql .= "='" . $conn->real_escape_string($data) . "'";
            break;
    }

    $sql .= " WHERE t.`id`=" . $conn->real_escape_string($_REQUEST['tgt_id']);

    if (!$conn->real_query($sql)) {
        error_log($conn->error);
        Sagacity_Error::sql_handler($sql);

        return 'false';
    }

    return 'true';
}

function get_category_details($cat_id)
{
    global $db;
    $cat = $db->get_Category($cat_id);
    if (is_array($cat) && count($cat) && isset($cat[0]) && is_a($cat[0], 'ste_cat')) {
        $cat = $cat[0];
    }
    else {
        return 'no category found';
    }

    return json_encode(array(
        'id'      => $cat->get_ID(),
        'name'    => $cat->get_Name(),
        'analyst' => $cat->get_Analyst(),
        'sources' => $cat->get_Sources()
    ));
}
