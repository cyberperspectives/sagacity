<?php
/**
 * File: update.php
 * Author: Ryan Prather
 * Purpose: Perform update actions on db and files
 * Created: Sep 20, 2013
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 20, 2013 - File created
 *  - May 06, 2014 - Added pthreads libraries, sha1 comparison for php and apache config files, and database reload (does not dump)
 *  - Sep 1, 2016 - Copyright Updated and converted to constants
 *  - Oct 10, 2016 - Commented out code for copying php_pthread libraries.  Need to only do that if this is a Windows install.
 *  - Nov 7, 2016 - Moved MySQL password for database reloading to defaults-file
 *  - Nov 14, 2016 - Fixed bug with .sql files not being read and imported and formatting,
 *                   Added radio buttons to identify DB type (MySQL v. mariaDB),
 *                   Added checkbox to import sample_data.sql file
 *  - Dec 8, 2016 - Changed create table code to use default database engine (#25)
 *  - Dec 12, 2016 - Added parsing for engine attribute in table tag
 *  - Apr 5, 2017 - Formating, switch to using filter_input function instead of direct calls to superglobals,
 *                  Deleted commented out pthreads copy code, check for Windows system before attempting to copy config files
 *                  Removed processing old content, search for *routines.sql files, remove, and process after all other sql files
 *  - Jan 10, 2018 - Fixed bug with tables not being updated if they already exist
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';
include_once 'vendor/autoload.php';

$uname = filter_input(INPUT_POST, 'uname', FILTER_SANITIZE_STRING);
$pwd = filter_input(INPUT_POST, 'pwd', FILTER_SANITIZE_STRING);

if ($uname && $pwd) {
    set_time_limit(0);
    $successful = true;
    $restart_apache = false;
    $restart_mysql = false;
    $zip = new ZipArchive();
    // attempt to create a new database connection
    $conn = new mysqli(DB_SERVER, $uname, $pwd);
    if ($conn->connect_error) {
        die($conn->connect_error);
    }

    $conn->real_query("CREATE DATABASE IF NOT EXISTS `sagacity`");
    $conn->real_query("CREATE DATABASE IF NOT EXISTS `rmf`");

    $conn->select_db("sagacity");

    $db = new db_helper($conn);

    // clean /tmp directory
    array_map('unlink', glob("tmp/*.*"));

    $add_table = [];
    $reload = (boolean) filter_input(INPUT_POST, 'reload', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    $json = json_decode(file_get_contents(DOC_ROOT . "/db_schema.json"));

    if ($reload) {
        foreach (array_reverse($json->tables) as $table) {
            $db->c->select_db($table->schema);
            $db->drop($table->schema, $table->name);
        }
    }

    $host = '%';
    if (in_array(strtolower(DB_SERVER), ["localhost", "127.0.0.1"])) {
        $host = 'localhost';
    }

    print "<pre>";

    foreach ($json->tables as $table) {
        $db->c->select_db($table->schema);
        print "Checking {$table->schema}.{$table->name}" . PHP_EOL;

        if ($db->table_exists("sagacity", "settings")) {
            $db->select("settings", ['db_data'], [
                [
                    'field' => 'meta_key',
                    'op' => '=',
                    'value' => "{$table->schema}.{$table->name}"
                ]
            ]);
            $td = $db->execute();
            if (isset($td['db_data'])) {
                $jtable = json_decode($td['db_data']);
                if ($jtable == $table) {
                    continue;
                }
            }

            if ($db->table_exists($table->schema, $table->name)) {
                $fd = $db->field_data($table->schema, $table->name);
                foreach ($table->fields as $field) {
                    print "field: {$field->name}" . PHP_EOL;

                    if (!isset($fd[$field->name])) {
                        print "field doesn't exist" . PHP_EOL;
                        $db->alter_table($table->name, "add-column", $field);
                    } else {
                        $index = (isset($table->index) && is_array($table->index) && count($table->index) ? $table->index : null);
                        $sql = $db->field_check($fd[$field->name], $field, $table->primary_key, $index);

                        if (!is_null($sql)) {
                            $sql = "ALTER TABLE `{$table->schema}`.`{$table->name}` $sql";
                            $db->query_type = db_helper::ALTER_TABLE;
                            $db->execute(MYSQLI_BOTH, $sql);
                        }
                    }
                }

                if (isset($table->constraints) && is_array($table->constraints) && count($table->constraints)) {
                    foreach ($table->constraints as $con) {
                        if (!$db->is_constraint($con->id)) {
                            $sql .= "ALTER TABLE `{$table->schema}`.`{$table->name}`" .
                                " ADD CONSTRAINT `{$cont->id}` " .
                                "FOREIGN KEY (`{$con->local}`) " .
                                "REFERENCES `{$con->schema}`.`{$con->table}` (`{$con->field}`) " .
                                "ON DELETE " . (!is_null($con->delete) ? strtoupper($con->delete) : "NO ACTION") .
                                " ON UPDATE " . (!is_null($con->update) ? strtoupper($con->update) : "NO ACTION");

                            if (!$conn->real_query($sql)) {
                                die($conn->error);
                            }
                        }
                    }
                }

                $db->update("sagacity.settings", ['db_data' => json_encode($table)], [
                    [
                        'field' => 'meta_key',
                        'op' => '=',
                        'value' => "{$table->schema}.{$table->name}"
                    ]
                ]);
                $db->execute();
            } else {
                print "Creating {$table->schema}.{$table->name}" . PHP_EOL;
                $db->create_table_json($table);

                if (isset($table->triggers)) {
                    // see if the first entry is a drop statement, run it and remove for subsequent statements
                    if (substr($table->triggers[0], 0, 4) == 'DROP') {
                        $db->query($table->triggers[0]);
                        unset($table->triggers[0]);
                    }
                    // concatenate the trigger into one string
                    $trig = implode(" ", $table->triggers);
                    if (!$db->query(str_replace("{host}", $host, $trig))) {
                        print $trig . PHP_EOL;
                        die($db->error);
                    }
                }

                $db->insert("sagacity.settings", [
                    'meta_key' => "{$table->schema}.{$table->name}",
                    'db_data' => json_encode($table)
                ]);

                if (!$db->execute()) {
                    $help->debug(E_ERROR);
                }
            }
        } else {
            $db->create_table_json($table);
            $db->insert("sagacity.settings", [
                'meta_key' => "{$table->schema}.{$table->name}",
                'db_data' => json_encode($table)
            ]);

            $db->execute();
        }
    }

    $db->extended_insert("sagacity.settings", ['meta_key', 'meta_value'], [
        ['cpe-load-date', new DateTime('1970-01-01')],
        ['cpe-progress', 0],
        ['cpe-dl-progress', 0],
        ['cve-load-date', new DateTime('1970-01-01')],
        ['cve-progress', 0],
        ['cve-dl-progress', 0],
        ['nvd-cve-load-date', new DateTime('1970-01-01')],
        ['nvd-cve-progress', 0],
        ['nvd-cve-dl-progress', 0],
        ['stig-load-date', new DateTime('1970-01-01')],
        ['stig-progress', 0],
        ['stig-dl-progress', 0],
        ['nasl-load-date', new DateTime('1970-01-01')],
        ['nasl-progress', 0],
        ['nasl-dl-progress', 0]
    ]);
    $db->execute();

    /*
     * **********************************************************
     * Reload table data
     * ********************************************************** */
    if ($reload) {
        $defaults = <<<EOO
[client]
password="{$pwd}"
port=3306

EOO;
        file_put_contents(realpath(TMP) . "/defaults.tmp", $defaults);
        chdir(realpath(DOC_ROOT));
        $zip->open("Database_Baseline.zip");
        $zip->extractTo("Database_Baseline");
        chdir("Database_Baseline");
        $sql_files = glob("*.sql");
        $zip->close();

        $sample = (boolean) filter_input(INPUT_POST, 'sample_data', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if (!$sample) {
            if (($key = array_search('sample_data.sql', $sql_files)) !== false) {
                unset($sql_files[$key]);
                unlink('sample_data.sql');
            }
        }

        $routines = glob("*routines.sql");
        foreach ($routines as $file) {
            if (($key = array_search($file, $sql_files)) !== false) {
                unset($sql_files[$key]);
            }
        }

        if (count($sql_files)) {
            sort($sql_files);
            foreach ($sql_files as $file) {
                $cmd = realpath(DB_BIN) . " --defaults-file=\"" . realpath(TMP . "/defaults.tmp") . "\"" .
                    " --user={$uname}" .
                    " --host=" . DB_SERVER .
                    " --default-character-set=utf8 < \"$file\"";
                //print "$cmd".PHP_EOL;
                exec($cmd);
                unlink($file);
                print "Imported $file<br />";
                flush();
            }

            foreach ($routines as $file) {
                $cmd = realpath(DB_BIN) . " --defaults-file=\"" . realpath(TMP . "/defaults.tmp") . "\"" .
                    " --user={$uname}" .
                    " --host=" . DB_SERVER .
                    " --default-character-set=utf8 < \"$file\"";

                exec($cmd);
                unlink($file);
                print "Imported $file<br />";
                flush();
            }
        }
        unlink(realpath(TMP . "/defaults.tmp"));

        if (ping("cyberperspectives.com")) {
            try {
                $script = realpath(PHP_BIN) .
                    " -c " . realpath(PHP_CONF) .
                    " -f update_db.php" .
                    " -- --cpe --cve --stig";
                $process = new Cocur\BackgroundProcess\BackgroundProcess($script);
                $process->run();
            } catch (Exception $e) {
                die(print_r($e, true));
            }
        }
    }

    print "</pre><br />Updated complete<br />";
    if ($restart_apache) {
        print "Apache or PHP configuration files were updated, please restart Apache to enact changes<br />";
    }
    if ($restart_mysql) {
        print "MySQL configuration file was updated, please restart MySQL service to enact changes<br />";
    }
    print "Click <a href='/'>here</a> to resume";
    exit();
}

?>

<!DOCTYPE HTML>
<html>
    <head>
        <title>Update Sagacity</title>
        <script src='/style/5grid/jquery-1.11.3.min.js'></script>
    </head>

    <body>
        <form method='post' action='#'>
            MySQL User Name:
            <input type='text' name='uname' title='Must have permissions to create/alter tables' /><br />
            Password:
            <input type='password' name='pwd' /><br />
            <label for='reload_chk'>Reload data in database?</label>
            <input type='checkbox' name='reload' id='reload_chk' value='1' title='Deletes all tables and data then reloads with baseline data' /><br />
            <label for='sample_data'>Add sample data</label>
            <input type='checkbox' name='sample_data' id='sample_data' value='1' title='Add sample data to database' /><br />
            <input type='submit' name='submit' value='Update' />
        </form>
    </body>
</html>
