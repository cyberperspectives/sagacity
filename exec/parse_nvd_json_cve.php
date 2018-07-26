<?php
/**
 * File: parse_nvd_json_cve
 * Author: Ryan Prather <ryan.prather@cyberperspectives.com>
 * Purpose:
 * Created: Apr 29, 2018
 *
 * Copyright 2018: Cyber Perspective, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Apr 29, 2018 - File created
 *  - May 10, 2018 - Formatting and fixed performance issue on Windows (bug #403)
 *  - Jun 5, 2018 - Fix for bug #425
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';
include_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

ini_set('memory_limit', '2G');

$cmd = getopt("f:");

if (!isset($cmd['f']) || isset($cmd['h'])) {
    die(usage());
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
        break;
}

$log = new Logger("nvd_cve");
$log->pushHandler(new StreamHandler(LOG_PATH . "/nvd_cve.log", $log_level));

$db            = new db();
$json          = json_decode(file_get_contents($cmd['f']));
$existing_cves = [];

$db->help->select("cve_db", ['cve_id']);
$cves = $db->help->execute();
if (is_array($cves) && count($cves)) {
    foreach ($cves as $cve) {
        $existing_cves["{$cve['cve_id']}"] = 1;
    }
}

print "Currently " . count($existing_cves) . " in DB" . PHP_EOL . "Parsing: " . count($json->CVE_Items) . " items" . PHP_EOL;

$db_cpes      = [];
$new_cves     = [];
$new_cve_refs = [];
$new_cve_web  = [];
$sw_rows      = [];
$new          = 0;
$existing     = 0;

$db->help->select("software", ['id', 'cpe']);
$rows = $db->help->execute();
foreach ($rows as $row) {
    $db_cpes["{$row['cpe']}"] = $row['id'];
}

$cve_fields = [
    'cve_id', 'seq', 'status', 'phase', 'phase_date', 'desc'
];
$ref_fields = [
    'cve_seq', 'source', 'url', 'val'
];
$web_fields = [
    'cve_id', 'xml'
];

foreach ($json->CVE_Items as $cve) {
    if (!isset($existing_cves["{$cve->cve->CVE_data_meta->ID}"])) {
        $log->debug("Adding {$cve->cve->CVE_data_meta->ID}");
        $new++;

        $desc   = [];
        $status = null;
        $phase  = null;
        $cpes   = [];
        $name   = $cve->cve->CVE_data_meta->ID;
        $type   = $cve->cve->data_type;
        $seq    = $cve->cve->CVE_data_meta->ID;
        $pd     = new DateTime($cve->publishedDate);
        $lmd    = new DateTime($cve->lastModifiedDate);

        if (is_array($cve->cve->description->description_data) && count($cve->cve->description->description_data)) {
            foreach ($cve->cve->description->description_data as $d) {
                $desc[] = $d->value;
            }
        }

        $new_cves[] = [
            $name, $seq, $status, $phase, $pd, implode(PHP_EOL, $desc)
        ];

        if (is_array($cve->cve->references->reference_data) && count($cve->cve->references->reference_data)) {
            foreach ($cve->cve->references->reference_data as $ref) {
                $log->debug("Adding reference {$ref->url}");
                $new_cve_refs[] = [
                    $name, null, $ref->url, null
                ];
            }
        }

        if (is_array($cve->configurations->nodes) && count($cve->configurations->nodes)) {
            foreach ($cve->configurations->nodes as $n) {
                if (isset($n->cpe) && is_array($n->cpe) && count($n->cpe)) {
                    foreach ($n->cpe as $cpe) {
                        if (isset($cpe->cpe22Uri)) {
                            $cpes[] = $cpe->cpe22Uri;
                        }
                        elseif (isset($cpe->cpeMatchString)) {
                            $cpes[] = $cpe->cpeMatchString;
                        }
                    }
                }
            }
        }

        if (count($cpes)) {
            foreach ($cpes as $cpe) {
                if (isset($db_cpes["{$cpe}"])) {
                    $sw_rows[] = [$name, $db_cpes["{$cpe}"]];
                }
            }
        }

        print "*";
    }
    else {
        $existing++;
        print ".";
    }

    if (($new + $existing) % 100 == 0) {
        if (count($new_cves)) {
            $db->help->extended_insert("cve_db", $cve_fields, $new_cves, true);
            $db->help->execute();
        }

        if (count($new_cve_refs)) {
            $db->help->extended_insert("cve_references", $ref_fields, $new_cve_refs, true);
            $db->help->execute();
        }

        if (count($sw_rows)) {
            $db->help->extended_insert("cve_sw_lookup", ['cve_id', 'sw_id'], $sw_rows, true);
            $db->help->execute();
        }

        $new_cves     = [];
        $new_cve_refs = [];
        $new_cve_web  = [];
        $sw_rows      = [];

        print "\t" . ($existing + $new) . " completed" . PHP_EOL;

        $db->help->update("settings", ['meta_value' => number_format((($existing + $new) / count($json->CVE_Items)) * 100, 2)], [
            [
                'field' => 'meta_key',
                'value' => 'nvd-cve-progress'
            ]
        ]);
        $db->help->execute();
    }
}

if (count($new_cves)) {
    $db->help->extended_insert("cve_db", $cve_fields, $new_cves, true);
    $db->help->execute();
}

if (count($new_cve_refs)) {
    $db->help->extended_insert("cve_references", $ref_fields, $new_cve_refs, true);
    $db->help->execute();
}

if (count($sw_rows)) {
    $db->help->extended_insert("cve_sw_lookup", ['cve_id', 'sw_id'], $sw_rows, true);
    $db->help->execute();
}

unlink($cmd['f']);

print PHP_EOL;

function usage()
{
    print <<<EOF
Purpose: To import the National Vulnerability Database (NVD) CVE JSON files

Usage: php parse_nvd_json_cve.php -f={JSON file} [-h]

 -f={JSON file}     The CVE file to import
 -h                 This screen

EOF;
}
