<?php
/**
 * File: parse_nmap.php
 * Author: Ryan Prather
 * Purpose: Parse an nmap result file
 * Created: Jul 3, 2014
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
 *  - Jul 3, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter, and
 * 					updated function calls after class merger
 *  - Oct 24, 2016 - Fixed bug (#6) when parsing port data, and added exclusion for "[host down]"
 *  - Nov 7, 2016 - Added d parameter documentation
 *  - Dec 7, 2016 - Added check for "Interesting ports on {IP}" line
 *  - Jan 30, 2017 - Updated to use parse_config.ini file, and added populating new targets with shortened os software string if available.
 *  - Jan 21, 2019 - fixed filetype check for .nmap and .gnmap files.
 */
$cmd = getopt("f:", ['debug::', 'help::']);

if (!isset($cmd['f']) || isset($cmd['help'])) {
    die(usage());
}

$conf = parse_ini_file("parse_config.ini");

if (!$conf) {
    die("Could not find parse_config.ini configuration file");
}

chdir($conf['doc_root']);

include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';

chdir(TMP);
set_time_limit(0);

$db        = new db();
$base_name = basename($cmd['f']);
$err       = new Sagacity_Error($cmd['f']);

if (!file_exists($cmd['f'])) {
    $db->update_Running_Scan($base_name, ['name' => 'status', 'value' => 'ERROR']);
    $err->script_log("File not found", E_ERROR);
}

$db->update_Running_Scan($base_name, ['name' => 'pid', 'value' => getmypid()]);
$src = $db->get_Sources("NMAP");
$existing_scan = $db->get_ScanData($conf['ste'], $base_name);

if (is_array($existing_scan) && count($existing_scan)) {
    $scan = $existing_scan[0];
}
else {
    $mtime   = filemtime($cmd['f']);
    $dt      = DateTime::createFromFormat("U", $mtime);
    $ste     = $db->get_STE($conf['ste'])[0];
    $scan    = new scan(null, $src, $ste, 1, $base_name, $dt->format("Y-m-d"));
    $scan_id = $db->save_Scan($scan);
    $scan->set_ID($scan_id);
}

//echo "\$steid ($steid) will be used later\n";
# file is cool - reads the whole file into an array with one command...
$lines  = file($cmd['f']);
$target = [];
foreach ($lines as $line_num => $line) {
    $db->help->select("scans", ['status'], [
        [
            'field' => 'id',
            'op'    => '=',
            'value' => $scan->get_ID()
        ]
    ]);
    $thread_status = $db->help->execute();
    if ($thread_status['status'] == 'TERMINATED') {
        rename(realpath(TMP . "/{$scan->get_File_Name()}"), TMP . "/terminated/{$scan->get_File_Name()}");
        $err->script_log("File parsing terminated by user");
        die();
    }

    if (preg_match('/^[\r\n]+$/', $line)) {
        continue;
    } # skip blank lines
    $line = trim($line, "\t\n\r"); # chomp would be nice...
    $matches = [];
    if (!isset($filetype)) {
        if (preg_match('/\.nmap/', $cmd['f'])) {
			$filetype = "text";
		}
		elseif (preg_match('/\.gnmap/', $cmd['f'])) {
            $filetype = "grep";
        }
		elseif (preg_match('/Starting|\-oN/', $line)) {
            $filetype = "text";
        }
        elseif (preg_match('/\-oG/', $line)) {
            $filetype = "grep";
        }
        elseif (preg_match('/xml version/', $line)) {
            $filetype = "xml";
            break;
        }

        if ($line_num >= 1 && !isset($filetype)) {
            $err->script_log("ERROR File Type not found");
        }
    }

    if ($filetype == "text") {
        //echo "Text:$line_num: $line\n";
        if (preg_match("/Host is up|Not shown|PORT\s+STATE|\[host down\]/", $line)) {
            continue;
        }

        if (preg_match("/Interesting ports on ([\d\.]+)/", $line, $matches)) {
            $ip                      = $matches[1];
            $target[$ip]             = [];
            $target[$ip]['hostname'] = $ip;
        }
        elseif (preg_match("/Nmap scan report for ([^ ]+) \(([0-9\.]+)\)/", $line, $matches)) {
            $ip = $matches[2];
            if (preg_match('/\./', $matches[1])) {
                $name                    = explode('.', $matches[1]);
                $target[$ip]['hostname'] = $name[0];
                $target[$ip]['fqdn']     = $matches[1];
            }
            else {
                $target[$ip]['hostname'] = $matches[1];
            }
            $err->script_log($target[$ip]['hostname'] . ":$ip");
        }
        elseif (preg_match("/Nmap scan report for ([0-9\.]+)/", $line, $matches)) {
            $ip                      = $matches[1];
            $target[$ip]['hostname'] = "";
            $err->script_log($target[$ip]['hostname'] . ":$ip");
        }
        elseif (preg_match("/^Discovered ([a-z]+) port (\d+)\/([udtcp]+) on (\d\.]+)$/", $line, $matches)) {
            $state = $matches[1];
            $port  = $matches[2];
            $proto = $matches[3];
            $ip    = $matches[4];

            $target[$ip][$proto][$port]['state'] = $state;

            $err->script_log("\t$ip:$port:$proto:$state");
        }
        elseif (preg_match("/Other addresses.*: ([0-9\. ]+)/", $line, $matches)) {
            $target[$ip]['otherips'] = $matches[1];
            $err->script_log("\tOther:" . $matches[1]);
        }
        elseif (preg_match('/(\d+)\/([udtcp]+)\s+(\S+)\s+(\S+)/', $line, $matches)) {
            if ($matches[3] == 'unknown') {
                continue;
            }
            $port  = $matches[1];
            $proto = $matches[2];
            if (!empty($ip)) {
                $target[$ip][$proto][$port]['state'] = $matches[3];
                $target[$ip][$proto][$port]['iana']  = $matches[4];
            }
            $err->script_log("\t$port:$proto:$matches[3]:$matches[4]");

            if (preg_match("/\d+\/[udtcp]+\s+\S+\s+\S+\s+(.*)/", $line, $matches)) {
                $target[$ip][$proto][$port]['banner'] = $matches[1];
                $err->script_log("\tBanner:$matches[1]");
            }
        }
        elseif (preg_match('/MAC Address: ([A-F0-9:]+)/', $line, $matches)) {
            $target[$ip]['mac'] = $matches[1];
            if (preg_match('/MAC Address: [A-F0-9:]+\s+\((.*)\)/', $line, $matches)) {
                $target[$ip]['description'] = $matches[1];
                $err->script_log("\t" . $target[$ip]['mac'] . ": Interface:$matches[1]");
            }
        }
        elseif (preg_match('/Service Info: OS: (\S+);/', $line, $matches)) {
            $target[$ip]['OS'] = $matches[1];
            if (preg_match('/Service Info: OS: \S+; CPE: (.+)/', $line, $matches)) {
                $target[$ip]['cpe'] = $matches[1];
            }
            else {
                $target[$ip]['cpe'] = null;
            }
            $err->script_log("\t" . $target[$ip]['OS'] . ", " . $target[$ip]['cpe']);
        }
    }
    elseif ($filetype == "grep") {
        $err->script_log("Grep:$line_num: $line" . PHP_EOL);
        # -oG grep format is not recommended - it discards helpful information like hostname
        if (preg_match("/Host: ([0-9\.]+) \((.*)\)\s+(Ports|Protocols):(.*)/", $line, $matches)) {
            $ip = $matches[1];
            if (preg_match('/\./', $matches[2])) {
                $name                    = explode('.', $matches[2]);
                $target[$ip]['hostname'] = $name[0];
                $target[$ip]['fqdn']     = $matches[2];
            }
            else {
                $target[$ip]['hostname'] = $matches[2];
            }
            $err->script_log("$ip:" . $matches[2]);
            $type         = $matches[3]; # will be used later when we support IP protocol scans
            $ports_string = $matches[4];
            $ports_list   = explode(",", $ports_string);
            foreach ($ports_list as $port_num => $port_str) {
                # fields: port, state, owner, service/sunRPC/banner
                # need to read the manual for grepable!
                $port_info                            = explode("/", $port_str);
                $port                                 = $port_info[0];
                $proto                                = $port_info[2];
                $target[$ip][$proto][$port]['state']  = $port_info[1];
                $target[$ip][$proto][$port]['iana']   = $port_info[4];
                $target[$ip][$proto][$port]['banner'] = $port_info[6];
                $err->script_log("\t$port:$proto:" . $port_info[1] . $port_info[4]);
                $err->script_log("\tBanner: " . $port_info[6]);
            }
        }
    } # end Grep parsing
} # end foreach line in file

if ($filetype == "xml") {
    $err->script_log("Parsing XML");
    $xml   = new DOMDocument();
    $xml->load($cmd['f']);
    $hosts = getValue($xml, "/nmaprun/host", null, true);
    $count = 0;
    foreach ($hosts as $host) {
        $addrs = getValue($xml, "address", $host, true);
        foreach ($addrs as $addr) {
            $addrtype = $addr->getAttribute("addrtype");
            if ($addrtype == "ipv4") {
                $ip = $addr->getAttribute("addr");
            }
            elseif ($addrtype == "mac") {
                $vendor = $addr->getAttribute("vendor");
                $mac    = $addr->getAttribute("addr");
            }
        }
        $target[$ip]['hostname']    = getValue($xml, "hostnames/hostname[@type='user']/@name", $host);
        $target[$ip]['mac']         = $mac;
        $target[$ip]['description'] = $vendor;
        # Iterate through ports
        $ports                      = getValue($xml, "ports/port", $host, true);
        foreach ($ports as $portxml) {
            $portid = $portxml->getAttribute("portid");
            $proto  = $portxml->getAttribute("protocol");

            if ($proto == 'tcp') {
                $port = $db->get_TCP_Ports($portid)[0];
            }
            else {
                $port = $db->get_UDP_Ports($portid)[0];
            }

            $target[$ip][$proto][$portid]['state']  = getValue($xml, "state/@state", $portxml);
            $target[$ip][$proto][$portid]['iana']   = getValue($xml, "service/@name", $portxml);
            $product                                = getValue($xml, "service/@product", $portxml);
            $version                                = getValue($xml, "service/@version", $portxml);
            $extrainfo                              = getValue($xml, "service/@extrainfo", $portxml);
            $target[$ip][$proto][$portid]['banner'] = "$product $version $extrainfo";

            $port->set_Banner("$product $version $extrainfo");
            $port->set_IANA_Name(getValue($xml, "service/@name", $portxml));

            if ($proto == 'tcp') {
                $tcp_ports[] = $port;
            }
            else {
                $udp_ports[] = $port;
            }

            //echo "$portid, $proto, " .$target[$ip][$proto][$portid]['banner'] ."\n";
        } # end foreach port

        $target[$ip]['OS'] = getValue($xml, "os/osmatch/@name", $host);
        $err->script_log($target[$ip]['OS']);
    } # end foreach host
} # end XML parsing
###################################

$db->update_Running_Scan($base_name, ['name' => 'host_count', 'value' => count($target)]);
$count  = 0;
$tgt_ip = null;

foreach ($target as $ip => $tgt) {
    # get target ID
    $tgt_id = 0;
    if (!in_array($ip, ['0.0.0.0', '127.0.0.1', '::0'])) {
        $tgt_ip = $ip;
    }
    if ($tgt['hostname']) {
        $tgt_id = $db->check_Target($conf['ste'], $tgt['hostname']);
    }
    if (!$tgt_id) {
        $tgt_id = $db->check_Target($conf['ste'], $ip);
    }
    if (!$tgt_id) { # insert
        $sw      = $db->get_Software("cpe:/o:generic:generic:-")[0];
        $tgt_obj = new target(($tgt['hostname'] ? $tgt['hostname'] : $ip));
        $tgt_obj->set_STE_ID($conf['ste']);
        //$tgt_obj->set_Notes("New target found by NMap");
        $tgt_obj->set_OS_ID($sw->get_ID());
        $tgt_obj->set_PP_Flag(true);
        if ($sw->get_Shortened_SW_String()) {
            $tgt_obj->set_OS_String($sw->get_Shortened_SW_String());
        }
        else {
            $tgt_obj->set_OS_String($sw->get_SW_String());
        }
        $tgt_obj->set_Location(($conf['location'] ? $conf['location'] : ''));

        $tgt_obj->interfaces["{$ip}"] = new interfaces(null, null, null, $ip, null, $tgt_obj->get_Name(), (isset($tgt['fqdn']) ? $tgt['fqdn'] : $tgt_obj->get_Name()), (isset($tgt['description']) ? $tgt['description'] : ""));

        if (isset($tgt['tcp'])) {
            foreach ($tgt['tcp'] as $port_num => $port) {
                if ($port['state'] != 'open') {
                    continue;
                }
                $tcp = $db->get_TCP_Ports($port_num)[0];
                if (!empty($port['banner'])) {
                    $tcp->set_Banner($port['banner']);
                }
                $tcp->set_IANA_Name($port['iana']);
                //$tcp->set_Notes("Found in scan file " . $scan->get_File_Name());

                $tgt_obj->interfaces["{$ip}"]->add_TCP_Ports($tcp);
            }
        }

        if (isset($tgt['udp'])) {
            foreach ($tgt['udp'] as $port_num => $port) {
                if ($port['state'] != 'open') {
                    continue;
                }
                $udp = $db->get_UDP_Ports($port_num)[0];
                if (!empty($port['banner'])) {
                    $udp->set_Banner($port['banner']);
                }
                $udp->set_IANA_Name($port['iana']);
                //$udp->set_Notes("Found in scan file " . $scan->get_File_Name());

                $tgt_obj->interfaces["{$ip}"]->add_UDP_Ports($udp);
            }
        }

        $tgt_obj->set_ID($tgt_id = $db->save_Target($tgt_obj, false));
    }
    else { #Update
        $db_tgt = $db->get_Target_Details($conf['ste'], $tgt_id)[0];
        $db_tgt->set_PP_Flag(true);

        if (isset($tgt['tcp'])) {
            foreach ($tgt['tcp'] as $port_num => $port) {
                if ($port['state'] != 'open') {
                    continue;
                }
                $tcp = new tcp_ports(null, $port_num, $port['iana'], (isset($port['banner']) ? $port['banner'] : ""), "");
                if (!isset($db_tgt->interfaces["{$ip}"])) {
                    $db_tgt->interfaces["{$ip}"] = new interfaces(null, null, null, $ip, null, $tgt['hostname'], $tgt['hostname'], (isset($tgt['description']) ? $tgt['description'] : ""));
                }

                if ($db_tgt->interfaces["{$ip}"]->is_TCP_Port_Open($port_num)) {
                    $db_tgt->interfaces["{$ip}"]->update_TCP_Port($tcp);
                }
                else {
                    $db_tgt->interfaces["{$ip}"]->add_TCP_Ports($tcp);
                }
            }
        }

        if (isset($tgt['udp'])) {
            foreach ($tgt['udp'] as $port_num => $port) {
                if ($port['state'] != 'open') {
                    continue;
                }
                $udp = new udp_ports(null, $port_num, $port['iana'], (isset($port['banner']) ? $port['banner'] : ""), "");
                if (!isset($db_tgt->interfaces["{$ip}"])) {
                    $interface               = new interfaces(null, $tgt_id, null, $ip, null, $tgt['hostname'], $tgt['hostname'], (isset($tgt['description']) ? $tgt['description'] : ""));
                    $db_tgt->interfaces["{$ip}"] = $interface;
                }

                if ($db_tgt->interfaces["{$ip}"]->is_UDP_Port_Open($port_num)) {
                    $db_tgt->interfaces["{$ip}"]->update_UDP_Port($udp);
                }
                else {
                    $db_tgt->interfaces["{$ip}"]->add_UDP_Ports($udp);
                }
            }
        }

        $db->save_Target($db_tgt, false);
    }

    $count++;
    $db_tgt = $db->get_Target_Details($conf['ste'], $tgt_id)[0];

    $hl               = new host_list();
    $hl->setTargetId($db_tgt->get_ID());
    $hl->setTargetName($db_tgt->get_Name());
    $hl->setTargetIp($tgt_ip);
    $hl->setFindingCount(0);
    $hl->setScanError(false);

    $scan->add_Target_to_Host_List($hl);
    $db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => ($count / count($target) * 100)]);
    $db->update_Running_Scan($base_name, ['name' => 'last_host', 'value' => $db_tgt->get_Name()]);
}

$db->post_Processing();
$db->update_Scan_Host_List($scan);
$db->update_Running_Scan($base_name, ['name' => 'perc_comp', 'value' => 100, 'complete' => 1]);
if (!isset($cmd['debug'])) {
    rename($cmd['f'], TMP . "/nmap/" . $base_name);
}

function usage()
{
    print <<<EOO
Purpose: To import an NMap result file

Usage: php parse_nmap.php -s={ST&E ID} -f={NMap result file} -d={Document root} [--debug] [--help]

 -s={ST&E ID}       The ST&E ID this result file is being imported for
 -f={NMap file}     The result file to import (will import text, XML, and grepable files)
 -d={Document Root} The document root of the web server

 --debug            Debugging output
 --help             This screen

EOO;
}
