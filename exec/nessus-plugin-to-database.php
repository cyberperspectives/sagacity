<?php

/**
 * File: nessus-plugin-to-database.php
 * Author: Ryan Prather
 * Purpose: Script to read .NASL files and import them to the database
 * Created: Jan 15, 2017
 *
 * Copyright 2017: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 15, 2017 - File created
 *  - Jan 31, 2017 - Competed testing, ready for prime time
 *  - Apr 5, 2017 - Delete file if error in parsing, check for TMP/nessus_plugins and LOG_PATH/nessus_plugins.log
 */
error_reporting(E_ALL);

include_once 'config.inc';
include_once "database.inc";
include_once "helper.inc";

$cmd = getopt("f:h::", array("help::", "debug::"));

if (isset($cmd['h']) || isset($cmd['help']) || !isset($cmd['f'])) {
  die(usage());
}
elseif (!file_exists($cmd['f'])) {
  die("Could not find file specified {$cmd['f']}\n");
}

check_path(TMP . "/nessus_plugins", true);
check_path(LOG_PATH . "/nessus_plugins.log");

$db = new db();

file_put_contents("check.log", "checking plugin file {$cmd['f']}");

$nasl = new nasl($cmd['f']);

if (!isset($nasl->{'id'})) {
  unlink($cmd['f']);
  die;
}

if (isset($cmd['debug'])) {
  print_r($nasl);
}

$plugin_id = 0;
$file_date = null;

$db->help->select("sagacity.nessus_plugins", array('plugin_id', 'file_date'), [
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
  file_put_contents(LOG_PATH . "/nessus_plugins.log", "Updating {$nasl->id}\n", FILE_APPEND);

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
  else {
    print "$db->help->sql\n";
  }
}
elseif (!$plugin_id) {
  file_put_contents(LOG_PATH . "/nessus_plugins.log", "Inserting {$nasl->id}\n", FILE_APPEND);

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
  else {
    print "$db->help->sql\n";
  }
}
else {
  file_put_contents(LOG_PATH . "/nessus_plugins.log", "No changes to plugin {$nasl->id}\n", FILE_APPEND);
}

$params = array();
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

if (!isset($cmd['debug'])) {
  unlink($cmd['f']);
}

function usage() {
  print <<<EOL
Purpose: This script is for reading NASL files and adding them to the database

Usage: php nessus-plugin-to-database.php -f={NASL file to parse} [--debug]

NOTE: This will create a file for any CVE's not found in the database. An update of CVE's should be done first.

  -f={NASL file}    The .nasl file to parse

  --debug           This will output what was parsed by the script and NOT add anything to the database

EOL;
}
