<?php
/**
 * File: nessus-plugin-to-database.php
 * Author: Ryan Prather
 * Purpose: Script to read .NASL files and import them to the database
 * Created: Jan 15, 2017
 *
 * Copyright 2017-2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 15, 2017 - File created
 *  - Jan 31, 2017 - Competed testing, ready for prime time
 *  - Apr 5, 2017 - Delete file if error in parsing, check for TMP/nessus_plugins and LOG_PATH/nessus_plugins.log
 *  - Apr 29, 2018 - Updated to Monolog library and cleaned up script
 */
error_reporting(E_ALL);

include_once 'config.inc';
include_once "database.inc";
include_once "helper.inc";
include_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

$cmd = getopt("f:h::", ["help::", "debug::"]);

if (isset($cmd['h']) || isset($cmd['help']) || !isset($cmd['f'])) {
    die(usage());
}
elseif (!file_exists($cmd['f'])) {
    die("Could not find file specified {$cmd['f']}\n");
}

$log_level = Logger::ERROR;
switch (LOG_LEVEL) {
    case E_WARNING:
        $log_level = Logger::WARNING;
        break;
    case E_NOTICE:
        $log_level = Logger::NOTICE;
        break;
    case E_DEBUG:
        $log_level = Logger::DEBUG;
}

if (isset($cmd['debug']) && $cmd['debug']) {
    $log_level = Logger::DEBUG;
}

$stream = new StreamHandler("php://output", $log_level);
$stream->setFormatter(new LineFormatter("%datetime% %level_name% %message%" . PHP_EOL, "H:i:s.u"));

$log = new Logger("nasl_plugin");
$log->pushHandler(new StreamHandler(LOG_PATH . "/nessus_plugins/{$cmd['f']}.log", $log_level));
$log->pushHandler($stream);

$db        = new db();
$nasl      = new nasl($cmd['f']);
$plugin_id = 0;
$file_date = null;

if (!isset($nasl->{'id'})) {
    //unlink($cmd['f']);
    $log->critical("No ID available");
    die;
}

if (isset($cmd['debug'])) {
    $log->debug("", [$nasl]);
}

$db->help->select("sagacity.nessus_plugins", ['plugin_id', 'file_date'], [
    [
        'field' => 'plugin_id',
        'op'    => '=',
        'value' => $nasl->id
    ]
]);

if ($row = $db->help->execute()) {
    $plugin_id = $row['plugin_id'];
    $file_date = DateTime::createFromFormat("U", $row['file_date']);
}

if (($plugin_id && !is_a($file_date, "DateTime")) ||
    (is_a($file_date, "DateTime") && isset($nasl->last_modification) && is_a($nasl->last_modification, "DateTime") &&
    $file_date->format("U") < $nasl->last_modification->format("U"))) {
    $log->info("Updating {$nasl->id}");

    $db->help->update("sagacity.nessus_plugins", [
        'file_name' => basename($cmd['f']),
        'file_date' => (is_a($file_date, "DateTime") ? $file_date->format("U") : filemtime($cmd['f']))], [
        [
            'field' => 'plugin_id',
            'op'    => '=',
            'value' => $nasl->id
        ]
    ]);
    if (!isset($cmd['debug'])) {
        if (!$db->help->execute()) {
            throw(new Exception("Failed to update the plugin {$nasl->id}", E_WARNING));
        }
    }
}
elseif (!$plugin_id) {
    $log->info("Inserting {$nasl->id}");

    $params = [
        'plugin_id' => $nasl->id,
        'oid'       => isset($nasl->oid) ? $nasl->oid : null,
        'name'      => isset($nasl->name) ? $nasl->name : null,
        'copyright' => isset($nasl->copyright) ? $nasl->copyright : null,
        'version'   => isset($nasl->rev) ? $nasl->rev : null,
        'file_name' => basename($cmd['f']),
        'file_date' => isset($nasl->last_modification) && is_a($nasl->last_modification, "DateTime") ?
        $nasl->last_modification->format("U") : null
    ];

    $db->help->insert("sagacity.nessus_plugins", $params, true);
    if (!isset($cmd['debug'])) {
        if (!$db->help->execute()) {
            throw(new Exception("Failed to insert a new plugin {$nasl->id}", E_WARNING));
        }
    }
}
else {
    $log->info("No changes to plugin {$nasl->id}");
}

$params = [];
if (isset($nasl->ref)) {
    foreach ($nasl->ref as $key => $refs) {
        if (is_array($refs)) {
            foreach ($refs as $ref) {
                $params[] = [
                    $nasl->id,
                    $key,
                    $ref
                ];
            }
        }
        else {
            $params[] = [
                $nasl->id,
                $key,
                $refs
            ];
        }
    }
}

unset($nasl->ref);
unset($nasl->oid);
unset($nasl->name);
unset($nasl->copyright);
unset($nasl->rev);
unset($nasl->last_modification);

foreach ((array) $nasl as $field => $val) {
    if (($field == 'id') || (is_array($val) && count($val) > 1)) {
        continue;
    }
    elseif (is_array($val) && count($val) == 1 && isset($val[0])) {
        $val = $val[0];
    }
    $params[] = [
        $nasl->id,
        $field,
        $val
    ];
}

if (count($params)) {
    $db->help->extended_insert("sagacity.nessus_meta", [
        'plugin_id', 'type', 'val'
        ], $params, true);
}

if (!isset($cmd['debug'])) {
    $db->help->execute();
}
else {
    print $db->help->sql . PHP_EOL;
}


function usage()
{
    print <<<EOL
Purpose: This script is for reading NASL files and adding them to the database

Usage: php nessus-plugin-to-database.php -f={NASL file to parse} [--debug]

NOTE: This will create a file for any CVE's not found in the database. An update of CVE's should be done first.

  -f={NASL file}    The .nasl file to parse

  --debug           This will output what was parsed by the script and NOT add anything to the database

EOL;
}
