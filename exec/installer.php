<?php
/**
 * File: installer.php
 * Author: Ryan Prather <ryan.prather@cyberperspectives.com>
 * Purpose: This script runs the installer processes
 * Created: Nov 28, 2017
 *
 * Copyright 2017: Cyber Perspective, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Nov 28, 2017 - File created
 *  - Dec 27, 2017 - Fixed bug with SCG showing empty, and added download progress meta keys
 *  - Jan 2, 2018 - Add sleep to fix bug #357 race condition
 *  - Jan 10, 2018 - Formatting
 */
include_once 'helper.inc';
include_once 'vendor/autoload.php';

use Cocur\BackgroundProcess\BackgroundProcess;

set_time_limit(0);

$params       = [
    'filter' => FILTER_SANITIZE_STRING,
    'flag'   => FILTER_NULL_ON_FAILURE
];
$db_step      = [
    'doc-root'      => $params,
    'pwd-file'      => $params,
    'tmp-path'      => $params,
    'log-path'      => $params,
    'log-level'     => $params,
    'db-server'     => $params,
    'root-uname'    => $params,
    'root-pwd'      => $params,
    'conf-root-pwd' => $params,
    'web-pwd'       => $params,
    'local-path'    => $params,
    'action'        => $params,
    'sample-data'   => ['filter' => FILTER_VALIDATE_BOOLEAN],
    'cpe'           => ['filter' => FILTER_VALIDATE_BOOLEAN],
    'cve'           => ['filter' => FILTER_VALIDATE_BOOLEAN],
    'stig'          => ['filter' => FILTER_VALIDATE_BOOLEAN]
];
$company_step = [
    'company'       => $params,
    'comp-add'      => $params,
    'last-modified' => $params,
    'creator'       => $params,
    'system-class'  => $params,
    'classified-by' => $params,
    'scg'           => $params,
    'derived-on'    => $params,
    'declassify-on' => $params
];
$options_step = [
    'flatten'       => ['filter' => FILTER_VALIDATE_BOOLEAN],
    'wrap-text'     => ['filter' => FILTER_VALIDATE_BOOLEAN],
    'notifications' => ['filter' => FILTER_VALIDATE_BOOLEAN],
    'port-limit'    => [
        'filter'  => FILTER_VALIDATE_INT,
        'flag'    => FILTER_REQUIRE_ARRAY,
        'options' => ['max_range' => 10000]
    ],
    'max-results'   => [
        'filter'  => FILTER_VALIDATE_INT,
        'flag'    => FILTER_REQUIRE_ARRAY,
        'options' => ['min_range' => 1, 'max_range' => 20]
    ],
    'output-format' => [
        'filter'  => FILTER_VALIDATE_REGEXP,
        'flag'    => FILTER_NULL_ON_FAILURE,
        'options' => ['regexp' => "/xlsx|xls|html|csv|pdf|ods/"]
    ]
];

$step = filter_input(INPUT_POST, 'step', FILTER_VALIDATE_INT);

if ($step == 0) {
    $fields = filter_input_array(INPUT_POST, $db_step);
    save_Database($fields);
}
elseif ($step == 1) {
    $fields = filter_input_array(INPUT_POST, $company_step);
    save_Company($fields);
}
elseif ($step == 2) {
    $fields = filter_input_array(INPUT_POST, $options_step);
    save_Options($fields);
}

/**
 * Function to save database details and load data
 *
 * @param array $params
 */
function save_Database($params)
{
    $config = file_get_contents("config.inc", FILE_USE_INCLUDE_PATH);

    $php   = null;
    $mysql = null;
    if (strtolower(substr(PHP_OS, 0, 3)) == 'lin') {
        if (file_exists('/bin/php')) {
            $php = realpath("/bin/php");
        }
        else {
            die(json_encode(['error' => 'Cannot find the PHP executable']));
        }

        if (file_exists('/bin/mysql')) {
            $mysql = realpath('/bin/mysql');
        }
        else {
            die(json_encode(['error' => 'Cannot find the MySQL executable']));
        }
    }
    else {
        if (file_exists("c:/xampp/php/php.exe")) {
            $php = realpath("c:/xampp/php/php.exe");
        }
        else {
            die(json_encode(['error' => 'Cannot find the PHP executable']));
        }

        if (file_exists("c:/xampp/mysql/bin/mysql.exe")) {
            $mysql = realpath("c:/xampp/mysql/bin/mysql.exe");
        }
        else {
            die(json_encode(['error' => 'Cannot find the MySQL executable']));
        }
    }

    my_str_replace("{DOC_ROOT}", realpath($params['doc-root']), $config);
    my_str_replace("{PWD_FILE}", $params['pwd-file'], $config);
    my_str_replace("'{E_ERROR}'", "E_{$params['log-level']}", $config);
    my_str_replace("{PHP_BIN}", $php, $config);
    my_str_replace("{PHP_CONF}", realpath(php_ini_loaded_file()), $config);
    my_str_replace("{DB_SERVER}", $params['db-server'], $config);
    my_str_replace("{DB_BIN}", $mysql, $config);
    my_str_replace("@new", "@step1", $config);

    if (!file_exists($params['tmp-path'])) {
        if (!mkdir($params['tmp-path'])) {
            die(json_encode(['error' => 'Temporary path is not available. Please create and give Apache user write permissions']));
        }
    }
    elseif (!is_dir($params['tmp-path']) || !is_writable($params['tmp-path'])) {
        die(json_encode(['error' => 'TMP path is not a writable directory to Apache']));
    }
    my_str_replace("{TMP_PATH}", $params['tmp-path'], $config);

    if (!file_exists($params['log-path'])) {
        if (!mkdir($params['log-path'])) {
            die(json_encode(['error' => 'Log path is not available. Please create and give Apache user write permissions']));
        }
    }
    elseif (!is_dir($params['log-path']) || !is_writable($params['log-path'])) {
        die(json_encode(['error' => 'Log path is not a writable directory by Apache']));
    }
    my_str_replace("{LOG_PATH}", $params['log-path'], $config);

    file_put_contents("{$params['doc-root']}/config.inc", $config);

    include_once 'config.inc';
    include_once 'database.inc';

    /* ---------------------------------
     * 	CREATE DB PASSWORD FILE
     * --------------------------------- */
    $enc_pwd = my_encrypt($params['web-pwd']);
    file_put_contents(DOC_ROOT . "/" . PWD_FILE, $enc_pwd);

    if (isset($params['conf-root-pwd']) && $params['conf-root-pwd'] == $params['root-pwd']) {
        $db = new mysqli(DB_SERVER, $params['root-uname'], '', 'mysql');
        if (!$db->real_query("UPDATE user SET Password=PASSWORD('{$db->real_escape_string($params['root-pwd'])}') WHERE User='root'")) {
            error_log($db->error);
            die(json_encode(['error' => "Could not set the root users password, manually set it and try this again"]));
        }

        $db->real_query("FLUSH PRIVILEGES");
        unset($db);
    }

    $successful = true;
    $zip        = new ZipArchive();
    $db         = new mysqli(DB_SERVER, $params['root-uname'], $params['root-pwd'], 'mysql');
    if ($db->connect_errno && $db->connect_errno == 1045) {
        die(json_encode(['error' => 'There was a problem with the user/password combination, please go back and try again']));
    }
    elseif ($db->connect_errno) {
        die(json_encode(['error' => "There was an error connecting to the database on " . DB_SERVER . " with user {$params['root-uname']} and {$params['root-pwd']}"]));
    }
    $help = new db_helper($db);

    $svr_ver = (int) $db->server_version;
    $maj     = (int) ($svr_ver / 10000);
    $svr_ver -= ($maj * 10000);
    $min     = (int) ($svr_ver / 100);
    $svr_ver -= ($min * 100);
    $update  = $svr_ver;

    if (version_compare("{$maj}.{$min}.{$update}", "5.5", "<=")) {
        die(json_encode(['error' => "The current version of MySQL needs to be at least 5.5"]));
    }

    // set the character set and default database
    $db->set_charset("utf8");

    /* --------------------------------
     *    USER MANAGEMENT
     * -------------------------------- */
    $help->delete("mysql.user", null, [
        [
            'field' => 'User',
            'op'    => '=',
            'value' => ''
        ]
    ]);
    $help->execute();

    $errors = [];

    /* --------------------------------
     *    SCHEMA MANAGEMENT
     * -------------------------------- */
    if (!$db->real_query("CREATE DATABASE IF NOT EXISTS `rmf`")) {
        $errors[] = $db->error;
    }
    if (!$db->real_query("CREATE DATABASE IF NOT EXISTS `sagacity`")) {
        $errors[] = $db->error;
    }
    $db->real_query("DROP DATABASE IF EXISTS cdcol");
    $db->real_query("DROP DATABASE IF EXISTS phpmyadmin");
    $db->real_query("DROP DATABASE IF EXISTS test");

    /* --------------------------------
     *    SET SCHEMA PERMISSIONS
     * -------------------------------- */
    $host = '%';
    if (in_array(strtolower(DB_SERVER), ["localhost", "127.0.0.1"])) {
        $host = 'localhost';
    }

    $help->select("mysql.user", ["COALESCE(COUNT(1), 0) AS 'count'"], [
        [
            'field' => 'User',
            'op'    => '=',
            'value' => 'web'
        ]
    ]);
    if (!$help->execute()['count']) {
        if (!$db->real_query("CREATE USER 'web'@'$host' IDENTIFIED BY '{$db->real_escape_string($params['web-pwd'])}'")) {
            $errors[] = $db->error;
        }
    }
    else {
        if (!$db->real_query("SET PASSWORD FOR 'web'@'$host' = PASSWORD('{$db->real_escape_string($params['web-pwd'])}')")) {
            $errors[] = $db->error;
        }
    }

    if (!$db->real_query("GRANT CREATE TEMPORARY TABLES, INSERT, DELETE, UPDATE, SELECT, TRIGGER ON `rmf`.* TO 'web'@'$host'")) {
        $errors[] = $db->error;
    }
    if (!$db->real_query("GRANT CREATE TEMPORARY TABLES, INSERT, DELETE, UPDATE, SELECT, TRIGGER ON `sagacity`.* TO 'web'@'$host'")) {
        $errors[] = $db->error;
    }

    if (count($errors)) {
        die(json_encode(['errors' => implode("<br />", $errors)]));
    }

    $db->real_query("FLUSH PRIVILEGES");
    chdir(realpath(DOC_ROOT));

    $json = json_decode(file_get_contents("db_schema.json"));

    foreach ($json->tables as $table) {
        Sagacity_Error::err_handler("Creating {$table->schema}.{$table->name}");
        $help->create_table_json($table);

        if (isset($table->triggers)) {
            // see if the first entry is a drop statement, run it and remove for subsequent statements
            if (substr($table->triggers[0], 0, 4) == 'DROP') {
                $db->real_query($table->triggers[0]);
                unset($table->triggers[0]);
            }
            // concatenate the trigger into one string
            $trig = implode(" ", $table->triggers);
            if (!$db->real_query(str_replace("{host}", $host, $trig))) {
                die($db->error);
            }
        }

        $help->insert("sagacity.settings", [
            'meta_key' => "{$table->schema}.{$table->name}",
            'db_data'  => json_encode($table)
            ], true);

        if (!$help->execute()) {
            $help->debug(E_WARNING, "JSON for {$table->schema}.{$table->name} table was not pushed to database");
        }
    }

    $help->extended_insert("settings", ["meta_key", "meta_value"], [
        ['cpe-load-date', new DateTime('1970-01-01')],
        ['cpe-progress', 0],
        ['cpe-dl-progress', 0],
        ['cve-load-date', new DateTime('1970-01-01')],
        ['cve-progress', 0],
        ['cve-dl-progress', 0],
        ['stig-load-date', new DateTime('1970-01-01')],
        ['stig-progress', 0],
        ['stig-dl-progress', 0],
        ['nasl-load-date', new DateTime('1970-01-01')],
        ['nasl-progress', 0],
        ['nasl-dl-progress', 0]
        ], true);
    $help->execute();

    /*
     * ***********************************************************
     * Load table data
     * ***********************************************************
     */
    chdir(DOC_ROOT);
    $zip->open("Database_Baseline.zip");
    $zip->extractTo("Database_Baseline");
    chdir("Database_Baseline");
    $sql_files = glob("*.sql");
    $zip->close();

    if (!$params['sample-data']) {
        if (($key = array_search("sample_data.sql", $sql_files)) !== false) {
            unset($sql_files[$key]);
            unlink("sample_data.sql");
        }
    }

    $defaults = <<<EOO
[client]
password="{$params['root-pwd']}"
port=3306

EOO;
    file_put_contents(realpath(TMP) . "/defaults.tmp", $defaults);

    $routines = glob("*routines.sql");
    foreach ($routines as $file) {
        if (($key = array_search($file, $sql_files)) !== false) {
            unset($sql_files[$key]);
        }
    }

    if (count($sql_files)) {
        sort($sql_files);
        foreach ($sql_files as $file) {
            $output = [];
            $cmd    = realpath(DB_BIN) . " --defaults-file=\"" . realpath(TMP . "/defaults.tmp") . "\"" .
                " --user={$params['root-uname']}" .
                " --host=" . DB_SERVER .
                " --default-character-set=utf8 < \"$file\"";
            exec($cmd, $output);

            if (preg_grep("/Access Denied/i", $output)) {
                $errors[]   = $output;
                $successful = false;
            }
            else {
                unlink($file);
            }
        }

        foreach ($routines as $file) {
            $str = file_get_contents($file);
            my_str_replace("{host}", $host, $str);
            file_put_contents($file, $str);

            $cmd = realpath(DB_BIN) . " --defaults-file=\"" . realpath(TMP . "/defaults.tmp") . "\"" .
                " --user={$params['root-uname']}" .
                " --host=" . DB_SERVER .
                " --default-character-set=utf8 < \"$file\"";

            exec($cmd);
            unlink($file);
            flush();
        }
    }

    if (count($errors)) {
        print json_encode(['errors' => implode("<br />", $errors)]);
        return;
    }

    unlink(realpath(TMP . "/defaults.tmp"));
    rmdir(realpath(DOC_ROOT . "/Database_Baseline"));

    $cpe    = null;
    $cve    = null;
    $stig   = null;
    $action = null;
    if ($params['cpe']) {
        $cpe = " --cpe";
    }

    if ($params['cve']) {
        $cve = " --cve";
    }

    if ($params['stig']) {
        $stig = " --stig";
    }

    $msg = null;
    if ($params['action'] == 'do' || $params['action'] == 'po') {
        $action = " --{$params['action']}";
        $msg    = "Files need to be placed in {doc_root}/tmp for parsing to work correctly";
    }

    print json_encode(['success' => true, 'msg' => $msg]);

    if (!is_null($cpe) || !is_null($cve) || !is_null($stig)) {
        $script  = realpath(PHP_BIN) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/update_db.php") .
            " --{$cpe}{$cve}{$stig}{$action}";
        $process = new BackgroundProcess($script);
        $process->run();
    }
}

/**
 * Function to save company information
 *
 * @param array $fields
 */
function save_Company($fields)
{
    $config = file_get_contents("config.inc", FILE_USE_INCLUDE_PATH);

    $scg_date     = new DateTime($fields['derived-on']);
    $declass_date = new DateTime($fields['declassify-on']);

    if (!is_a($scg_date, "DateTime") || !is_a($declass_date, "DateTime")) {
        print json_encode(['error' => 'Error parsing the dates']);
        return;
    }

    my_str_replace("{COMPANY}", $fields['company'], $config);
    my_str_replace("{COMP_ADD}", $fields['comp-add'], $config);
    my_str_replace("{LAST_MODIFIED_BY}", $fields['last-modified'], $config);
    my_str_replace("{CREATOR}", $fields['creator'], $config);
    my_str_replace("{SYSTEM_CLASS}", $fields['system-class'], $config);
    my_str_replace("{CLASSIFIED_BY}", $fields['classified-by'], $config);
    my_str_replace("{SCG}", $fields['scg'], $config);
    my_str_replace("{DERIVED_ON}", $scg_date->format("Y-m-d"), $config);
    my_str_replace("{DECLASSIFY_ON}", $declass_date->format("Y-m-d"), $config);
    my_str_replace("@step1", "@step2", $config);

    file_put_contents(dirname(dirname(__FILE__)) . "/config.inc", $config);

    print json_encode(['success' => true]);
}

/**
 * Function to save Sagacity options
 *
 * @param array $fields
 */
function save_Options($fields)
{
    $config = file_get_contents("config.inc", FILE_USE_INCLUDE_PATH);

    my_str_replace("'{FLATTEN}'", ($fields['flatten'] ? 'true' : 'false'), $config);
    my_str_replace("'{WRAP_TEXT}'", ($fields['wrap-text'] ? 'true' : 'false'), $config);
    my_str_replace("'{NOTIFICATIONS}'", ($fields['notifications'] ? 'true' : 'false'), $config);
    my_str_replace("'{PORT_LIMIT}'", $fields['port-limit'], $config);
    my_str_replace("'{MAX_RESULTS}'", $fields['max-results'], $config);
    my_str_replace("{ECHECKLIST_FORMAT}", $fields['output-format'], $config);
    my_str_replace("@step2", "", $config);

    file_put_contents(dirname(dirname(__FILE__)) . "/config.inc", $config);

    print json_encode(['success' => true]);
}
