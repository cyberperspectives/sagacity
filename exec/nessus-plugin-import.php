<?php
/**
 * File: nessus-plugin-import.php
 * Author: Ryan Prather
 * Purpose: Script to import all Nessus plugins from *.nasl files
 * Created: Jan 5, 2015
 *
 * Portions Copyright 2016-2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 5, 2015 - File created
 *  - Sep 1, 2016 - Copyright updated, converted to constants, and added file header
 *  - Jan 30, 2017 - Updated for platform independence and formatting
 *  - Jan 31, 2017 - Completed testing, ready for prime time
 *  - Feb 15, 2017 - Store existing plugin IDs in memory for evaluation to check if we should actually run the script,
 *                   Fixed error with PHP_BIN not being defined for some weird reason
 *  - May 24, 2018 - Added parsing for plugins installed on the local machine
 *                   Added DateTimeDiff helper class
 */
include_once 'config.inc';
include_once "database.inc";
include_once "helper.inc";

$cmd = getopt("h::", ["help::"]);

if (isset($cmd['h']) || isset($cmd['help'])) {
    die(usage());
}

$db = new db();
$time = new DateTimeDiff();

if (!file_exists(TMP . "/nessus_plugins")) {
    mkdir(TMP . "/nessus_plugins");
}

$nasl_ids = [];
$db->help->select("sagacity.nessus_plugins", ['plugin_id', 'file_date']);
if ($rows     = $db->help->execute()) {
    foreach ($rows as $row) {
        $nasl_ids[$row['plugin_id']] = DateTime::createFromFormat("U", $row['file_date']);
    }
}

chdir(TMP . '/nessus_plugins');
$files = glob("*.nasl");

if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
    if (file_exists(getenv("%ProgramData%") . "/Tenable/Nessus/nessus/plugins")) {
        chdir(getenv("%ProgramData%") . "/Tenable/Nessus/nessus/plugins");
        $files = array_merge($files, glob("*.nasl"));
    }
}
elseif (strtolower(substr(PHP_OS, 0, 3)) == 'lin') {
    if (file_exists("/opt/nessus/lib/nessus/plugins") && is_readable("/opt/nessus/lib/nessus/plugins")) {
        chdir("/opt/nessus/lib/nessus/plugins");
        $files = array_merge($files, glob("*.nasl"));
    }

    if (file_exists("/opt/sc/data/nasl") && is_readable("/opt/sc/data/nasl")) {
        chdir("/opt/sc/data/nasl");
        $files = array_merge($files, glob("*.nasl"));
    }
}

$files = array_unique($files);

print "Found " . count($files) . " NASL files\nStarted at {$time->getStartClockTime()}\n";

chdir(DOC_ROOT . "/exec");

// Query database to build an array of existing plugins to compare against on import
$existing_plugins = [];
$db->help->select("nessus_plugins", ['plugin_id', 'file_date']);
$rows             = $db->help->execute();
if (is_array($rows) && count($rows)) {
    foreach ($rows as $row) {
        $existing_plugins[$row['plugin_id']] = DateTime::createFromFormat("U", $row['file_date']);
    }
}

// Sort the files and loop over them
natsort($files);
$threads        = [];
$count          = 0;
$total_complete = 0;
foreach ($files as $file) {
    $db->help->select("nessus_plugins", ['plugin_id', 'file_date'], [
        [
            'field' => 'file_name',
            'value' => basename($file)
        ]
    ]);
    $row = $db->help->execute();

    if (!isset($row['file_name']) || is_null($row['file_date']) || filemtime(TMP . "/nessus_plugins/$file") > $row['file_date']) {
        $comp = number_format(($x / count($files)) * 100, 2);
        print "\r$comp%";

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/nessus-plugin-to-database.php") . " --" .
            " -f=\"" . realpath(TMP . "/nessus_plugins/$file") . "\"";

        $threads[] = new Cocur\BackgroundProcess\BackgroundProcess($script);
        end($threads)->run();

        //sleep(1);
        $count++;
        $total_complete++;

        if ($count > 1000) {
            $db->set_Setting("nasl-progress", $comp);

            foreach ($threads as $k => $t) {
                if (!$t->isRunning()) {
                    unset($threads[$k]);
                    $count--;
                }
            }
        }
    }
}

$db->set_Setting("nasl-dl-progress", 100);
$db->set_Setting("nasl-progress", 100);
$db->set_Setting("nasl-count", $total_complete);

$time->stopClock();

print "\nFinished at {$time->getEndClockTime()}\nTotal Time: {$time->getTotalDiffString()}\n";

function usage()
{
    print <<<EOF
Purpose: The purpose of this script is to update the CVE, CPE, and CCE databases.  Script will sleep for 3 seconds between actions to allow you review the results.

Usage: php nessus-plugin-import.php [-h|--help]

 -h|--help          This screen

EOF;
}
