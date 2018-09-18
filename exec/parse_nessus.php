<?php
/**
 * File: parse_nessus.php
 * Author: Ryan Prather
 * Purpose: Background script to parse Nessus result files
 * Created: Feb 26, 2014
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
 *  - Feb 26, 2014 - File created
 *  - Jun 17, 2014 - Added parsing for system ports
 *  - Sep 1, 2016 - Copyright Updated, added CWD parameter, and
 * 					fixed bugs
 *  - Oct 24, 2016 - Updated class extension after rename from XMLParser to scan_xml_parser
 * 					 Updated PHP_DOC comments
 * 					 Added and updated E_DEBUG constant
 * 					 And fixed bug with OS determination
 *  - Nov 7, 2016 - Added d parameter documentation, added a ton of PHP_DOC comments, and added tons of debugging statements
 *  - Nov 9, 2016 - Simplified OS detection in HostProperties_end function
 *  - Jan 30, 2017 - Updated to use parse_config.ini file, and added populating new targets with shortened os software string if available.
 *  - Feb 15, 2017 - Added error message and die if parse_config.ini is not present
 *  - Mar 4, 2017 - Fixed parsing of Windows 2003 Server and Oracle Solaris
 *  - Mar 22, 2017 - Check for multi-lined operating-system tag and only use first line,
 *                   If software not found using operating-system tag string then assign cpe:/o:generic:generic,
 *                   Replaced instances of removed setter functions to add_Reference function
 *  - Apr 5, 2017 - Fixed bug with some content being overwritten due to parsing tags multiple times,
 *                  Fixed bug with plugins not being assigned to the orphan checklist,
 *                  Fixed bug with script not reading listening TCP ports correctly,
 *                  Removed commented out content
 *  - May 13, 2017 - Removed adding note when not listening on any TCP 4/6 ports, also fixed error in compliance solution
 *  - Jun 27, 2017 - Fixed bug with target classifications not being set and ensure that file exists
 *  - Jul 21, 2017 - Check solution tag to make sure it's not 'n/a' before assigning, fixed software detection bug in n22869 method
 *  - Oct 27, 2017 - Fix to convert '*' to '0.0.0.0' or '::' and validate IP's before making interface
 *  - Nov 25, 2017 - Fixed bug #345
 *  - Jan 16, 2018 - Updated to use host_list class
 *  - Jun 4, 2018 - Fixed bug #424 (IP address not pulled when name used for host)
 */
error_reporting(E_ALL);

$cmd = getopt("f:", ['debug::', 'help::']);

if (isset($cmd['help']) || !isset($cmd['f'])) {
    die(usage());
}

if (!file_exists("parse_config.ini")) {
    die("You must create parse_config.ini file with required parameters");
}

$conf = parse_ini_file("parse_config.ini");

if (!$conf) {
    die("Could not find parse_config.ini configuration file");
}

chdir($conf['doc_root']);

include_once 'config.inc';
include_once 'helper.inc';
include_once 'xml_parser.inc';

Sagacity_Error::err_handler("Starting parse_nessus.php");

chdir(TMP);
set_time_limit(0);

$base_name = basename($cmd['f']);

if (!file_exists($cmd['f'])) {
    die("File {$cmd['f']} could not be found");
}

/**
 * Class to perform stream parsing of Nessus XML result file
 */
class nessus_parser extends scan_xml_parser
{

    /**
     * The host that is currently being parsed
     *
     * @var nessus_target
     */
    var $host;

    /**
     * The plugin ID that is currently being parsed
     *
     * @var int
     */
    var $plugin;

    /**
     * The target being parsed
     *
     * @var target
     */
    var $tgt;

    /**
     * The tag being parsed
     *
     * @var int
     */
    var $tag;

    /**
     * Counter
     *
     * @var int
     */
    var $count;

    /**
     * Variable to store if there was an error in the scanner reading this target
     *
     * @var boolean
     */
    var $host_scan_error = false;

    /**
     * Variable to store any host notes if there are errors in the scan
     *
     * @var string
     */
    var $host_scan_notes = null;

    /**
     * Replacement CPE's because Nessus is messed up and they don't use the NIST CPEs
     *
     * @var array:string
     */
    private $sw_translation = [
        "cpe:\/a:microsoft:ie:([\d]+)[\d\.]+.*"             => "cpe:/a:microsoft:internet_explorer:$1",
        "cpe:\/a:oracle:jre:1\.7\.0:update04.*"             => "cpe:/a:oracle:jre:1.7.0:update4",
        "cpe:\/a:oracle:jre:1\.7\.0:update60.*"             => "cpe:/a:oracle:jre:1.7.0:update_60",
        "cpe:\/o:cisco:ios_xe.*"                            => "cpe:/o:cisco:ios_xe:-",
        "cpe:\/o:microsoft:windows_xp::sp([\d]+).*"         => "cpe:/o:microsoft:windows_xp:-:sp$1",
        "cpe:\/o:microsoft:windows_7::sp([\d]+):x([\d]+).*" => "cpe:/o:microsoft:windows_7:-:sp$1:x$2",
        "cpe:\/o:microsoft:windows_2003_server::sp([\d]).*" => "cpe:/o:microsoft:windows_2003_server:-:sp$1",
        "cpe:\/o:microsoft:windows_server_2008:r2::x64.*"   => "cpe:/o:microsoft:windows_server_2008:r2",
        "cpe:\/o:redhat:enterprise_linux:([\d]+)::.*"       => "cpe:/o:redhat:enterprise_linux:$1",
        "cpe:\/o:sun:sunos:([\d]+)::x([\d]+).*"             => "cpe:/o:oracle:solaris:$1",
        "cpe:\/o:centos:centos:([\d]+).*"                   => "cpe:/o:centos:centos:$1",
    ];

    /**
     * List of plugin IDs to skip because they do not have any real info in them
     *
     * @var array:int
     */
    private $plugins_to_skip = [
        10150, 10223, 10335, 10397, 10785, 10919, 11002, 11011, 11936,
        22319, 24269, 25220, 34220, 42898, 53335, 54615, 55472, 57033,
        64582, 70331, 72482, 72663
    ];

    /**
     * Constructor
     *
     * @param int $ste_id_in
     * @param string $fname_in
     */
    function __construct($ste_id_in, $fname_in)
    {
        parent::__construct($this, $ste_id_in, $fname_in);
        $this->host_list = [];
        $this->count     = 0;
        $this->type      = 'nessus';

        if ($this->debug) {
            $this->log->script_log("Ready to parse {$this->file}", E_DEBUG);
        }
    }

    function NessusClientData_v2_Report_ReportHost($attrs)
    {
        global $conf;

        $this->tag               = [];
        $this->host              = new nessus_target();
        $this->new_findings      = [];
        $this->updated_findings  = [];
        $this->host_scan_error   = false;
        $this->host_scan_notes   = null;
        $this->tgt_finding_count = 0;
        $tgt_id                  = $this->db->check_Target($this->ste_id, $attrs['name']);
        if ($tgt_id) {
            $tgt = $this->db->get_Target_Details($this->ste_id, $tgt_id);
            if (is_array($tgt) && count($tgt) && isset($tgt[0]) && is_a($tgt[0], 'target')) {
                $this->tgt = $tgt[0];
            }
            else {
                Sagacity_Error::err_handler("Unable to find target with IP {$attrs['name']}", E_ERROR);
            }
            $this->tgt->set_Netstat_Connections("");
        }
        else {
            $this->tgt = new target($attrs['name']);
            $this->tgt->set_STE_ID($this->ste_id);
            $this->tgt->set_Location(($conf['location'] ? $conf['location'] : null));
        }

        if (validation::valid_ip($attrs['name'])) {
            $this->host->ip = $attrs['name'];
        }
    }

    function NessusClientData_v2_Report_ReportHost_HostProperties_tag($attrs)
    {
        if (isset($attrs['name'])) {
            $this->tag_id             = $attrs['name'];
            $this->tag[$this->tag_id] = null;
            if (preg_match("/MS\d{2}\-\d{3}/", $this->tag_id)) {
                $this->host->missing_patches[$this->tag_id] = null;
            }
        }
        else {
            $this->tag_id = null;
        }
    }

    function NessusClientData_v2_Report_ReportHost_HostProperties_tag_data($data)
    {
        $match = [];
        switch ($this->tag_id) {
            case (preg_match("/netstat\-listen\-udp[46]/", $this->tag_id) ? true : false):
                unset($this->tag[$this->tag_id]);
                break;
            case (preg_match("/netstat\-listen\-tcp([46])/", $this->tag_id) ? true : false):
                $pp   = explode(":", $data);
                $port = end($pp);
                if (is_numeric($port) && $port < 50000) {
                    $this->tag[$this->tag_id] .= $data;
                }
                else {
                    unset($this->tag[$this->tag_id]);
                }
                break;
            case (preg_match("/patch\-summary\-(cve\-num|cves|txt)\-([a-f0-9]+)/", $this->tag_id, $match) ? true : false):
                $this->tag['patch'][$match[2]][$match[1]] = $data;
                unset($this->tag[$this->tag_id]);
                break;
            case (preg_match("/ \-\> /", $data) && preg_match("/cpe/", $this->tag_id) ? true : false):
                $dash_pos                                 = strpos($data, ' ->');
                $data                                     = substr($data, 0, $dash_pos + 1);
                $this->tag[$this->tag_id]                 .= $data;
                break;
            case 'operating-system':
                if (strpos($data, "\n") !== false) {
                    $data = explode("\n", $data)[0];
                }
            // no break
            default:
                $this->tag[$this->tag_id] .= $data;
        }

        //print ".";
    }

    function NessusClientData_v2_Report_ReportHost_HostProperties_end()
    {
        $this->log->script_log("Start parsing HostProperties", E_DEBUG);
        $ip_port = [];
        $os      = [];

        if (isset($this->tag['netbios-name'])) {
            $this->log->script_log("Assigning netbios to target {$this->tag['netbios-name']}", E_DEBUG);
            $name   = explode(".", $this->tag['netbios-name']);
            if ($tgt_id = $this->db->check_Target($this->ste_id, current($name))) {
                $this->log->script_log("Found target with netbios-name {$this->tag['netbios-name']} ($tgt_id)", E_DEBUG);
                $tgt = $this->db->get_Target_Details($this->ste_id, $tgt_id);
                if (is_array($tgt) && count($tgt) && isset($tgt[0]) && is_a($tgt[0], 'target')) {
                    $this->tgt = $tgt[0];
                }
            }
            else {
                $this->log->script_log("Could not find the target", E_DEBUG);
            }
            $this->tgt->set_Name(current($name));
            $this->host->hostname = $this->tag['netbios-name'];
            if (isset($this->tag['host-fqdn'])) {
                $this->host->fqdn = $this->tag['host-fqdn'];
            }
        }
        elseif (isset($this->tag['host-fqdn'])) {
            $this->log->script_log("Assigning FQDN to target {$this->tag['host-fqdn']}", E_DEBUG);
            $name   = explode(".", $this->tag['host-fqdn']);
            if ($tgt_id = $this->db->check_Target($this->ste_id, current($name))) {
                $tgt = $this->db->get_Target_Details($this->ste_id, $tgt_id);
                if (is_array($tgt) && count($tgt) && isset($tgt[0]) && is_a($tgt[0], 'target')) {
                    $this->tgt = $tgt[0];
                }
            }
            $this->tgt->set_Name(current($name));
            $this->host->fqdn     = $this->tag['host-fqdn'];
            $this->host->hostname = explode(".", $this->tag['host-fqdn'])[0];
        }

        if (isset($this->tag['patch']) && is_array($this->tag['patch'])) {
            $this->host->missing_patches = array_merge($this->host->missing_patches, $this->tag['patch']);
            $this->tgt->set_Missing_Patches(print_r($this->host->missing_patches, true));
            unset($this->tag['patch']);
        }

        if ($this->debug) {
            $this->log->script_log("All HostProperties data: " . print_r($this->tag, true), E_DEBUG);
        }

        $cpe_keys = preg_grep("/cpe\-[\d]+/", array_keys($this->tag));
        if (count($cpe_keys)) {
            $this->log->script_log("Found " . count($cpe_keys) . " CPEs", E_DEBUG);
            foreach (array_values($cpe_keys) as $key) {
                $this->log->script_log("Finding software for CPE: {$this->tag[$key]}", E_DEBUG);
                $db_sw = null;

                foreach ($this->sw_translation as $old => $replacement) {
                    if (preg_match("/$old/i", $this->tag[$key])) {
                        $this->tag[$key] = preg_replace("/$old/i", "$replacement", $this->tag[$key]);
                        break;
                    }
                }

                $cpe = $this->tag[$key];
                if (($pos = strpos($cpe, " ")) !== false) {
                    $cpe = substr($cpe, 0, $pos);
                }
                $sw = new software($cpe, null);

                while (!$sw->get_ID()) {
                    $db_sw = $this->db->get_Software($sw->get_CPE());

                    if (!count($db_sw)) {
                        if ($sw->reduce_CPE()) {
                            break;
                        }
                    }
                    else {
                        $db_sw = $db_sw[0];
                        $sw    = $db_sw;
                    }
                }

                if (is_a($db_sw, 'software') && !$db_sw->is_OS()) {
                    if (!in_array($db_sw, $this->tgt->software)) {
                        $this->log->script_log("Adding software {$db_sw->get_CPE()} to {$this->tgt->get_Name()}", E_DEBUG);
                        $this->tgt->software[] = $db_sw;
                    }
                }
                elseif (is_a($db_sw, 'software') && $db_sw->is_OS()) {
                    $this->log->script_log("Setting OS to {$db_sw->get_CPE()} for {$this->tgt->get_Name()}", E_DEBUG);

                    $this->tgt->set_OS_ID($db_sw->get_ID());
                    if ($db_sw->get_Shortened_SW_String()) {
                        $this->tgt->set_OS_String($db_sw->get_Shortened_SW_String());
                    }
                    else {
                        $this->tgt->set_OS_String($db_sw->get_SW_String());
                    }
                }
            }

            if (!$this->tgt->get_OS_ID()) {
                if ($this->debug) {
                    $this->log->script_log("Could not determine OS so setting to generic", E_DEBUG);
                }

                $os = $this->db->get_Software("cpe:/o:generic:generic:-");
                if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
                    $os = $os[0];
                    $this->tgt->set_OS_ID($os->get_ID());
                    if ($os->get_Shortened_SW_String()) {
                        $this->tgt->set_OS_String($os->get_Shortened_SW_String());
                    }
                    else {
                        $this->tgt->set_OS_String($os->get_SW_String());
                    }
                }
            }
        }
        else {
            if (isset($this->tag['operating-system'])) {
                $os_regex = $this->db->get_Regex_Array("os");
                $os_arr   = software::identify_Software($os_regex, $this->tag['operating-system']);

                if (is_array($os_arr) && count($os_arr)) {
                    $os_arr = $os_arr[0];
                }

                if (!is_a($os_arr, 'software')) {
                    $os_arr = $this->db->get_Software("cpe:/o:generic:generic")[0];
                }

                if ($this->debug) {
                    $this->log->script_log("Identified this software ({$os_arr->get_CPE()}) from operating-system string {$this->tag['operating-system']}", E_DEBUG);
                }

                while (!$os_arr->get_ID()) {
                    $os = $this->db->get_Software($os_arr->get_CPE());

                    // was there software with that CPE
                    if (!count($os)) {
                        // if no software found, then reduce the CPE to potentially find matching software
                        //if($this->debug){$this->log->script_log("Reducing software count: {($os_arr->get_Reduct_Count()+1)}", E_DEBUG);}

                        if ($os_arr->reduce_CPE()) {
                            // if we weren't able to find anything within 4 attempts break out
                            break;
                        }
                    }
                    else {
                        // we found software
                        $os     = $os[0];
                        $os_arr = $os;  // this break's out of the above while loop
                    }
                }
            }

            // assign the detected software to the target
            if (is_a($os, 'software') && $os->get_ID()) {
                if ($this->debug) {
                    $this->log->script_log("Assigning {$os->get_SW_String()} ({$os->get_ID()}) to {$this->tgt->get_Name()}", E_DEBUG);
                }
                $this->tgt->set_OS_ID($os->get_ID());
                if ($os->get_Shortened_SW_String()) {
                    $this->tgt->set_OS_String($os->get_Shortened_SW_String());
                }
                else {
                    $this->tgt->set_OS_String($os->get_SW_String());
                }
            }
            else {
                // could not detect the operating system so assign the generic software and allow the user to specify
                if ($this->debug) {
                    $this->log->script_log("Assigning the generic OS to {$this->tgt->get_Name()}", E_DEBUG);
                }
                $os = $this->db->get_Software("cpe:/o:generic:generic:-")[0];
                $this->tgt->set_OS_ID($os->get_ID());
                if ($os->get_Shortened_SW_String()) {
                    $this->tgt->set_OS_String($os->get_Shortened_SW_String());
                }
                else {
                    $this->tgt->set_OS_String($os->get_SW_String());
                }
            }
        }

        $this->log->script_log("Assigning target classification to same as system", E_DEBUG);
        $sys = $this->db->get_System_By_STE_ID($this->ste_id);
        switch ($sys->get_Classification()) {
            case 'Classified':
                $this->tgt->classification = 'S';
                break;
            case 'Sensitive':
                $this->tgt->classification = 'FOUO';
                break;
            default:
                $this->tgt->classification = 'U';
        }

        if (isset($this->tag['smb-login-used'])) {
            $this->log->script_log("Assigning login used for target access", E_DEBUG);

            $this->tgt->set_Login($this->tag['smb-login-used']);
        }
        elseif (isset($this->tag['ssh-login-used'])) {
            $this->log->script_log("Assigning login used for target access", E_DEBUG);

            $this->tgt->set_Login($this->tag['ssh-login-used']);
        }

        if (isset($this->tag['mac-address'])) {
            $this->log->script_log("Adding MAC address to target");
            $this->host->mac = $this->tag['mac-address'];
        }

        if (!empty($this->host->ip) && validation::valid_ip($this->host->ip)) {
            if (!isset($this->tgt->interfaces[$this->host->ip])) {
                $this->log->script_log("Adding new interface to target with IP: {$this->host->ip}");
                $this->tgt->interfaces[$this->host->ip] = new interfaces(null, $this->tgt->get_ID(), null, $this->host->ip, null, $this->host->hostname, $this->host->fqdn, null);
            }
            else {
                $this->log->script_log("Interface already exists: {$this->host->ip}");
            }
        }

        if (!empty($this->tag['host-ip']) && validation::valid_ip($this->tag['host-ip'])) {
            if (!isset($this->tgt->interfaces[$this->tag['host-ip']])) {
                $this->log->script_log("Adding new interface to target with IP: {$this->tag['host-ip']}");
                $this->tgt->interfaces[$this->tag['host-ip']] = new interfaces(null, $this->tgt->get_ID(), null, $this->tag['host-ip'], null, $this->host->hostname, $this->host->fqdn, null);
            }
            else {
                $this->log->script_log("Interface already exists for target: {$this->tag['host-ip']}");
            }
        }

        $netstat_keys = preg_grep("/netstat\-established\-tcp/", array_keys($this->tag));
        $this->log->script_log("Start established tcp conns...found " . count($netstat_keys) . " connections", E_DEBUG);
        foreach (array_values($netstat_keys) as $key) {
            $src_dest = explode('-', $this->tag[$key]);

            $this->tgt->append_Connection("  TCP    " . str_pad($src_dest[0], 45) . str_pad($src_dest[1], 45) . "ESTABLISHED" . PHP_EOL);
        }

        $netstat_keys = preg_grep("/netstat\-listen\-tcp4/", array_keys($this->tag));
        $this->log->script_log("Start listening tcp4 conns...found " . count($netstat_keys) . " connections", E_DEBUG);
        if (between(count($netstat_keys), 1, PORT_LIMIT)) {
            foreach (array_values($netstat_keys) as $key) {
                // split into "ip:port" array
                $ip_port = explode(":", $this->tag[$key]);

                // skip this entry if it is not a valid IP
                if ($ip_port[0] == '*') {
                    $ip_port[0] = '0.0.0.0';
                }
                elseif (!validation::valid_ip($ip_port[0])) {
                    unset($this->tag[$key]);
                    continue;
                }

                //$this->host->netstat['listening']['tcp'][$ip_port[0]][] = $ip_port[1];
                $port            = $this->db->get_TCP_Ports($ip_port[1])[0];
                $port->set_Notes($port->get_Notes() . PHP_EOL . "Found in scan file " . $this->scan->get_File_Name());
                $port->listening = true;

                if (!isset($this->tgt->interfaces[$ip_port[0]])) {
                    $name                                   = ($this->host->hostname ? $this->host->hostname : explode(".", $this->host->fqdn)[0]);
                    $this->tgt->interfaces["{$ip_port[0]}"] = new interfaces(null, $this->tgt->get_ID(), null, $ip_port[0], null, $name, $this->host->fqdn, '');
                }

                if (empty($this->host->ip) && $ip_port[0] != '127.0.0.1' && $ip_port[0] != '0.0.0.0') {
                    $this->host->ip = $ip_port[0];
                }

                $this->tgt->interfaces["{$ip_port[0]}"]->add_TCP_Ports($port);
                $this->tgt->append_Connection("  TCP    " . str_pad($this->tag[$key], 45) . str_pad("0.0.0.0:0", 45) . "LISTENING" . PHP_EOL);
            }
        }
        else {
            $this->log->script_log("Skipping tcp4 ports because there are " . count($netstat_keys) . " listening", E_DEBUG);
        }

        $netstat_keys = preg_grep("/netstat\-listen\-tcp6/", array_keys($this->tag));
        $this->log->script_log("Start listening tcp6 conns...found " . count($netstat_keys) . " connections", E_DEBUG);
        if (between(count($netstat_keys), 1, PORT_LIMIT)) {
            foreach (array_values($netstat_keys) as $key) {
                if (preg_match("/(.*)\:(\d+)/", $this->tag[$key], $ip_port)) {
                    $ip_port[1] = str_replace(array("[", "]"), "", $ip_port[1]);

                    if ($ip_port[0] == '*') {
                        $ip_port[0] = '::';
                    }
                    elseif (!validation::valid_ip($ip_port[0])) {
                        unset($this->tag[$key]);
                        continue;
                    }

                    //$this->host->netstat['listening']['tcp'][$ip_port[1]][] = $ip_port[2];
                    $port            = $this->db->get_TCP_Ports($ip_port[2])[0];
                    $port->set_Notes($port->get_Notes() . PHP_EOL . "Found in scan file " . $this->scan->get_File_Name());
                    $port->listening = true;

                    if (!isset($this->tgt->interfaces[$ip_port[0]])) {
                        $name                               = ($this->host->hostname ? $this->host->hostname : explode(".", $this->host->fqdn)[0]);
                        $this->tgt->interfaces[$ip_port[0]] = new interfaces(null, $this->tgt->get_ID(), null, null, $ip_port[0], $name, $this->host->fqdn, '');
                    }

                    $this->tgt->interfaces[$ip_port[0]]->add_TCP_Ports($port);
                    $this->tgt->append_Connection("  TCP    " . str_pad($this->tag[$key], 45) . str_pad("[::]:0", 45) . "LISTENING" . PHP_EOL);
                }
            }
        }
        else {
            $this->log->script_log("Skipping tcp6 ports because there are " . count($netstat_keys) . " listening", E_DEBUG);
        }

        $this->tgt->set_PP_Flag(true);
        $this->tgt->set_ID($this->db->save_Target($this->tgt, false));

        $dt = DateTime::createFromFormat("D M d H:i:s Y", $this->tag["HOST_START"]);
        if ($dt < $this->scan->get_File_DateTime()) {
            $this->scan->set_File_DateTime($dt);
        }

        if ($this->debug) {
            $this->log->script_log("End parsing tag", E_DEBUG);
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem($attrs)
    {
        if (in_array($attrs['pluginID'], $this->plugins_to_skip)) {
            $this->skip   = true;
            $this->tag_id = $attrs['pluginID'];
            return;
        }
        else {
            $this->skip = false;
        }
        //print ".";
        $this->plugin           = new nessus_plugin();
        $this->plugin->port     = $attrs['port'];
        $this->plugin->svc_name = $attrs['svc_name'];
        $this->plugin->proto    = $attrs['protocol'];
        $this->plugin->sev      = $attrs['severity'];
        $this->plugin->id       = $attrs['pluginID'];
        $this->plugin->name     = $attrs['pluginName'];
        $this->plugin->family   = $attrs['pluginFamily'];

        if (preg_match("/2115[67]|33814|46689|66756/", $this->plugin->id)) {
            $this->plugin->result = new compliance();
        }
        else {
            $this->plugin->result = new nessus_result();
        }

        $this->plugin->result->cat    = 3;
        $this->plugin->result->status = 'Open';

        switch ($this->plugin->sev) {
            case 0:
                $this->plugin->result->status = "Not a Finding";
            case 1:
                break;
            case 2:
            case 3:
                $this->plugin->result->cat    = 2;
                break;
            default:
                $this->plugin->result->cat    = 1;
        }

        $this->plugin->db_plugin = $this->db->get_Nessus($this->plugin->id);
        $add_stig                = false;
        if (empty($this->plugin->db_plugin)) {
            $pdi    = new pdi(null, $this->plugin->result->cat, "NOW");
            $pdi->set_Short_Title($this->plugin->name);
            $pdi->set_Group_Title($this->plugin->name);
            $pdi->set_ID($pdi_id = $this->db->save_PDI($pdi));

            $stig = new stig($pdi_id, $this->plugin->id, $this->plugin->name);
            $this->db->add_Stig($stig);

            $this->plugin->db_plugin = new nessus($pdi_id, $this->plugin->id);
            $this->plugin->db_plugin->add_Reference('protocol', $this->plugin->port);
            $this->plugin->db_plugin->set_Name($this->plugin->name);
            $this->plugin->db_plugin->add_Reference('family', $this->plugin->family);

            $this->db->save_Nessus($this->plugin->db_plugin);
            $add_stig = true;
        }
        else {
            if (!$this->plugin->db_plugin->get_PDI_ID()) {
                $pdi    = new pdi(null, $this->plugin->result->cat, "NOW");
                $pdi->set_Short_Title($this->plugin->name);
                $pdi->set_Group_Title($this->plugin->name);
                $pdi->set_ID($pdi_id = $this->db->save_PDI($pdi));

                $stig = new stig($pdi_id, $this->plugin->id, $this->plugin->name);
                $this->db->add_Stig($stig);

                $this->plugin->db_plugin->set_PDI_ID($pdi_id);

                $add_stig = true;
            }
        }

        if ($add_stig) {
            $chk = $this->db->get_Checklist("Orphan");
            if (is_array($chk) && isset($chk[0]) && is_a($chk[0], 'checklist')) {
                $chk = $chk[0];
            }
        }

        $this->tgt_finding_count++;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_description_data($data)
    {
        $this->plugin->desc .= $data;
        $this->plugin->db_plugin->add_Reference('description', $data);

        if (preg_match("/Executing the command failed/i", $data)) {
            $this->plugin->result->status_override = true;
        }
        elseif (preg_match("/Nessus has not performed this query/i", $data)) {
            $this->plugin->result->status_override = true;
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_fname_data($data)
    {
        $this->plugin->fname .= $data;
        $this->plugin->db_plugin->set_FileName($data);
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_plugin_modification_date_data($data)
    {
        $this->plugin->mod_date = new DateTime($data);
        $this->plugin->db_plugin->set_FileDate($this->plugin->mod_date->format("U"));
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_plugin_name_data($data)
    {
        $this->plugin->name = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_plugin_publication_date_data($data)
    {
        $this->plugin->pub_date = new DateTime($data);
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_plugin_type_data($data)
    {
        $this->plugin->type = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_risk_factor_data($data)
    {
        $this->plugin->risk_factor = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_solution_data($data)
    {
        if ($data != 'n/a') {
            $this->plugin->solution = $data;
            $this->plugin->db_plugin->add_Reference('solution', $data);
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_synopsis_data($data)
    {
        $this->plugin->synopsis = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_see_also_data($data)
    {
        $this->plugin->see_also = explode(PHP_EOL, $data);
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_xref_data($data)
    {
        $src_id              = explode(":", $data);
        $this->plugin->ref[] = [
            'src' => strtolower($src_id[0]),
            'id'  => $src_id[1]
        ];
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cpe_data($data)
    {
        $cpes = explode(PHP_EOL, $data);
        foreach ($cpes as $cpe) {
            if (!in_array($cpe, $this->host->cpes)) {
                $this->host->cpes[] = $cpe;
            }
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_bid_data($data)
    {
        if (!isset($this->plugin->refs['bid'])) {
            $this->plugin->refs['bid'][] = $data;
        }
        elseif (!in_array($data, $this->plugin->refs['bid'], true)) {
            $this->plugin->refs['bid'][] = $data;
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cve_data($data)
    {
        if (!isset($this->plugin->refs['cve'])) {
            $this->plugin->refs['cve'][] = $data;
        }
        elseif (!in_array($data, $this->plugin->refs['cve'], true)) {
            $this->plugin->refs['cve'][] = $data;
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_osvdb_data($data)
    {
        if (!isset($this->plugin->refs['osvdb'])) {
            $this->plugin->refs['osvdb'][] = $data;
        }
        elseif (!in_array($data, $this->plugin->refs['osvdb'], true)) {
            $this->plugin->refs['osvdb'][] = $data;
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cvss_base_score_data($data)
    {
        $this->plugin->cvss_base = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cvss_vector_data($data)
    {
        $this->plugin->cvss_vector = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_plugin_output_data($data)
    {
        if (in_array($this->plugin->id, [20811, 22869, 22689])) {

        }
        elseif ($this->plugin->id == 10891) {

        }
        $this->plugin->result->plugin_output .= html_entity_decode($data);
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_script_version_data($data)
    {
        $ver = [];
        if (preg_match("/(\d+\.\d+)/", $data, $ver)) {
            $this->plugin->script_ver = $ver[1];
            $this->plugin->db_plugin->set_Version($ver[1]);
        }
        elseif (preg_match("/(\d+)/", $data, $ver)) {
            $this->plugin->script_ver = $ver[1];
            $this->plugin->db_plugin->set_Version($ver[1]);
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_stig_severity_data($data)
    {
        $this->plugin->result->cat = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_result_data($data)
    {
        if ($this->plugin->result->status_override) {
            return;
        }
        if ($data == 'PASSED') {
            $this->plugin->result->status = 'Not a Finding';
        }
        elseif ($data == 'FAILED') {
            $this->plugin->result->status = 'Open';
        }
        else {
            $this->plugin->result->status = 'Not Reviewed';
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_info_data($data)
    {
        $match = [];
        if (preg_match("/Title - ([^\n]+)/", $data, $match)) {
            $this->plugin->result->short_title = $match[1];
        }
        else {
            if (preg_match("/([^\n]+)/", $data, $match)) {
                $this->plugin->result->short_title = $match[1];
            }
        }

        if (preg_match("/<VulnDiscussion>(.*)<\/VulnDiscussion>/", $data, $match)) {
            $this->plugin->result->desc = $match[1];
        }
        elseif (preg_match("/^[^\n]\n(.*)$/", $data, $match)) {
            $this->plugin->result->desc = $match[1];
        }

        if (preg_match("/<IAControls>(.*)<\/IAControls>/", $data, $match)) {
            $this->plugin->result->ia_controls = preg_split("/, ?/", $match[1]);
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_audit_file_data($data)
    {
        $this->plugin->result->audit_file = $data;

        /**
         * @TODO check to see if there is already a OS assigned to the target
         * if not, parse audit file and see if we can identify the OS, then assign to target
         */
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_check_name_data($data)
    {
        $match = [];
        if (strpos($data, ":") !== false) {
            $check = explode(":", $data);
            if (is_array($check) && count($check) < 5) {
                if (preg_match("/(SV\-.*\_rule)/", $data, $match)) {
                    $sv_rule = $this->db->get_SV_Rule(null, $match[1]);
                    if (is_array($sv_rule) && count($sv_rule) && isset($sv_rule[0]) && is_a($sv_rule[0], 'sv_rule')) {
                        $this->plugin->result->sv_rule = $sv_rule[0];

                        $this->plugin->result->stig = $this->db->get_STIG_By_PDI($sv_rule[0]->get_PDI_ID());

                        if (empty($this->plugin->result->stig)) {
                            $this->plugin->result->stig = $sv_rule[0]->get_SV_Rule();
                        }
                    }
                }

                return;
            }
            $cce = $check[0];
            if ($cce != 'noCCE') {
                $this->plugin->result->cce = $cce;
            }

            $oval                          = $check[1];
            $this->plugin->result->oval_id = $oval;

            $sv_rule_id = $check[2];

            $sv_rule = $this->db->get_SV_Rule(null, $sv_rule_id);
            if (is_array($sv_rule) && count($sv_rule) && isset($sv_rule[0]) && is_a($sv_rule[0], 'sv_rule')) {
                $this->plugin->result->sv_rule = $sv_rule[0];

                $this->plugin->result->stig = $this->db->get_STIG_By_PDI($this->plugin->result->sv_rule->get_PDI_ID());

                if (empty($this->plugin->result->stig)) {
                    $this->plugin->result->stig = $sv_rule_id;
                }
            }
            else {
                print "can't find SV rule: $sv_rule_id" . PHP_EOL;
            }

            $chk = $this->db->get_Checklist(array('checklist_id' => $check[3], 'type' => 'manual'), true);

            if (!is_null($chk) && count($chk)) {
                $this->plugin->chk = $chk[0];
            }
        }
        elseif (preg_match("/(W[AW][\d]+\-[WA]+[\d]+) \((V0+[\d]+)\)/", $data, $match)) {
            $stig = $this->db->get_Stig($match[1], true);
            if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
                if (empty($this->plugin->result->stig)) {
                    $this->plugin->result->stig = $stig[0];
                }
            }
            else {
                $vms_id = preg_replace("/V0+/", "V-", $match[2]);
                $vms    = $this->db->get_GoldDisk($vms_id);
                if (is_array($vms) && count($vms) && isset($vms[0]) && is_a($vms[0], 'golddisk')) {
                    $this->plugin->result->stig = $this->db->get_STIG_By_PDI($vms[0]->get_PDI_ID());
                }
            }

            $this->plugin->result->short_title = $data;
        }
        elseif (preg_match("/(W[WAG][\d]+) \((V0+[\d]+)\)/", $data, $match)) {
            $stig = $this->db->get_Stig($match[1], true);
            if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
                if (empty($this->plugin->result->stig)) {
                    $this->plugin->result->stig = $stig[0];
                }
            }
            else {
                $vms_id = preg_replace("/V0+/", "V-", $match[2]);
                $vms    = $this->db->get_GoldDisk($vms_id);
                if (is_array($vms) && count($vms) && isset($vms[0]) && is_a($vms[0], 'golddisk')) {
                    $this->plugin->result->stig = $this->db->get_STIG_By_PDI($vms[0]->get_PDI_ID());
                }
            }

            $this->plugin->result->short_title = $data;
        }
        elseif (preg_match("/(JRE[^ ])/", $data, $match)) {
            $stig = $this->db->get_Stig($match[1]);
            if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
                if (empty($this->plugin->result->stig)) {
                    $this->plugin->result->stig = $stig[0];
                }
            }

            $this->plugin->result->short_title = $data;
        }
        else {
            $this->plugin->result->short_title = $data;
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_check_id_data($data)
    {

    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_reference_data($data)
    {
        $match = [];
        if (preg_match("/CAT\|([I]+)/", $data, $match)) {
            $this->plugin->result->cat = substr_count($match[1], "I");
        }

        if (preg_match("/CCI\|([^\,]+)/", $data, $match)) {
            $this->plugin->result->cci = $match[1];
        }

        if (empty($this->plugin->result->stig)) {
            if (preg_match("/STIG\-ID\|([^\,]+)/", $data, $match)) {
                $stig = $this->db->get_Stig($match[1]);
                if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
                    $this->plugin->result->stig = $stig[0];
                }
                else {
                    $this->plugin->result->stig = $match[1];
                }
            }
        }

        if (empty($this->plugin->result->sv_rule)) {
            if (preg_match("/Rule\-ID\|([^\,]+)/", $data, $match)) {
                $sv_rule = $this->db->get_SV_Rule(null, $match[1]);
                if (is_array($sv_rule) && count($sv_rule) && isset($sv_rule[0]) && is_a($sv_rule[0], 'sv_rule')) {
                    $this->plugin->result->sv_rule = $sv_rule[0];
                    $stig                          = $this->db->get_STIG_By_PDI($sv_rule[0]->get_PDI_ID());
                    if (is_a($stig, 'stig')) {
                        $this->plugin->result->stig = $stig;
                    }
                }
            }
        }

        if (empty($this->plugin->result->vms)) {
            if (preg_match("/Vuln\-ID\|([^\,]+)/", $data, $match)) {
                $match[1] = preg_replace("/V0+/", "V-", $match[1]);
                $vms      = $this->db->get_GoldDisk($match[1]);
                if (is_array($vms) && count($vms) && isset($vms[0]) && is_a($vms[0], 'golddisk')) {
                    $this->plugin->result->vms = $vms[0];
                }
                else {
                    $this->plugin->result->vms = $match[1];
                }
            }
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_see_also_data($data)
    {
        if (!empty($this->plugin->see_also)) {
            if (!is_array($this->plugin->see_also)) {
                $this->plugin->see_also = [0 => $this->plugin->see_also];
            }
        }
        else {
            $this->plugin->see_also = [];
        }
        $this->plugin->see_also = array_merge($this->plugin->see_also, explode(PHP_EOL, $data));
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_solution_data($data)
    {
        if (isset($this->plugin->result->solution) && !empty($this->plugin->result->solution)) {
            $this->plugin->result->solution .= $data;
        }
        elseif (isset($this->plugin->result->solution)) {
            $this->plugin->result->solution = $data;
        }
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_file_data($data)
    {
        $this->plugin->result->file = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_actual_value_data($data)
    {
        $this->plugin->result->actual_value = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_cm_compliance_policy_value_data($data)
    {
        $this->plugin->result->policy_value = $data;
    }

    function NessusClientData_v2_Report_ReportHost_ReportItem_end()
    {
        if ($this->skip) {
            $this->skip = false;
            return;
        }
        // add plugin if not present or update if it is.
        $note = '';
        if (is_a($this->plugin->result, 'compliance') && !empty($this->plugin->result->actual_value)) {
            $note = "Expected: {$this->plugin->result->policy_value}\rFound: {$this->plugin->result->actual_value}";
        }
        elseif (!empty($this->plugin->result->plugin_output)) {
            $note = $this->plugin->result->plugin_output;
        }
        else {
            $note = "Nessus provided no plugin_output";
        }

        $this->log->script_log("ReportItem_end-START: {$this->plugin->id}");
        //if($this->debug){$this->log->script_log("All data: ".print_r($this->plugin, true), E_DEBUG);}
        $func    = null;
        $finding = null;

        if (function_exists("n{$this->plugin->id}") && is_callable("n{$this->plugin->id}", false, $func)) {
            $this->log->script_log("Calling function n{$this->plugin->id}");
            $param = [&$this];
            call_user_func_array($func, $param);
            $this->log->script_log("Returned from calling function: $func");
        }
        elseif (in_array($this->plugin->id, [21156, 21157, 33814, 46689, 66756])) {
            $this->log->script_log("Starting compliance check", E_DEBUG);

            if (is_a($this->plugin->result->stig, "stig")) {
                $this->log->script_log("{$this->plugin->id} Processing compliance (" . $this->plugin->result->stig->get_ID() . ")");
                $finding = $this->db->get_Finding($this->tgt, $this->plugin->result->stig);
                $pdi     = $this->db->get_PDI($this->plugin->result->stig->get_PDI_ID());
                if (is_array($finding) && count($finding) && isset($finding[0])) {
                    $finding = $finding[0];

                    $orig_scan = $this->db->get_ScanData($this->ste_id, $finding->get_Scan_ID())[0];
                    //$orig_src = $this->db->get_Sources($orig_scan->get_Source_ID());

                    $finding->set_Original_Source($orig_scan->get_Source()->get_Name());
                    $finding->set_Scan_ID($this->scan->get_ID());
                    $finding->set_Finding_Status_By_String(
                        $finding->get_Deconflicted_Status($this->plugin->result->status)
                    );
                    $finding->set_Finding_Iteration($finding->get_Finding_Iteration() + 1);
                    $finding->prepend_Notes($note);

                    if (isset($this->updated_findings[$pdi->get_ID()])) {
                        $this->updated_findings[$pdi->get_ID()]->prepend_Notes($note);
                        $this->updated_findings[$pdi->get_ID()]->set_Finding_Status_By_String(
                            $this->updated_findings[$pdi->get_ID()]->get_Deconflicted_Status($this->plugin->result->status)
                        );
                        $this->updated_findings[$pdi->get_ID()]->set_Scan_ID($this->scan->get_ID());
                        $this->updated_findings[$pdi->get_ID()]->set_Finding_Iteration(
                            $this->updated_findings[$pdi->get_ID()]->get_Finding_Iteration() + 1
                        );
                    }
                    else {
                        $this->updated_findings[$pdi->get_ID()] = $finding;
                    }
                }
                else {
                    $tmp = new finding(null, $this->tgt->get_ID(), $this->plugin->result->stig->get_PDI_ID(), $this->scan->get_ID(), $this->plugin->result->status, "[{$this->tgt->get_Name()}]: {$note}", finding::NC, "Nessus", 1);
                    if (!is_null($pdi)) {
                        $tmp->set_Category($pdi->get_Category_Level());
                    }
                    else {
                        $tmp->set_Category($this->plugin->result->cat);
                    }

                    if (isset($this->new_findings[$tmp->get_PDI_ID()])) {
                        $this->new_findings[$tmp->get_PDI_ID()]->set_Finding_Status_By_String(
                            $this->new_findings[$tmp->get_PDI_ID()]->get_Deconflicted_Status($this->plugin->result->status)
                        );

                        $this->new_findings[$tmp->get_PDI_ID()]->prepend_Notes("[{$this->tgt->get_Name()}]: " . $note);
                    }
                    else {
                        $this->new_findings[$tmp->get_PDI_ID()] = $tmp;
                    }
                }
            }
            elseif (is_string($this->plugin->result->stig)) {
                // add pdi & stig?
                $pdi = new pdi(null, $this->plugin->result->cat, "NOW");
                $pdi->set_Short_Title($this->plugin->result->short_title);
                $pdi->set_Group_Title($this->plugin->result->short_title);
                $pdi->set_Description($this->plugin->desc);
                if (!empty($this->plugin->chk)) {
                    $pdi->set_ID($pdi_id = $this->db->save_PDI($pdi, $this->plugin->chk));
                }
                else {
                    $pdi->set_ID($pdi_id = $this->db->save_PDI($pdi));
                }

                $stig = new stig($pdi_id, $this->plugin->result->stig, $this->plugin->desc);
                $this->db->add_Stig($stig);

                $tmp = new finding(null, $this->tgt->get_ID(), $pdi->get_ID(), $this->scan->get_ID(), $this->plugin->result->status, "[" . $this->tgt->get_Name() . "]: " . $note, finding::NC, "Nessus", 1);
                $tmp->set_Category($this->plugin->result->cat);

                if (isset($this->new_findings[$tmp->get_PDI_ID()])) {
                    $this->new_findings[$tmp->get_PDI_ID()]->set_Finding_Status_By_String(
                        $this->new_findings[$tmp->get_PDI_ID()]->get_Deconflicted_Status($this->plugin->result->status)
                    );
                    $this->new_findings[$tmp->get_PDI_ID()]->append_Notes(PHP_EOL . "[" . $this->tgt->get_Name() . "]: " . $note);
                }
                else {
                    $this->new_findings[$pdi->get_ID()] = $tmp;
                }
            }
            else {
                $this->log->script_log("Could not determine STIG ID for {$this->plugin->id}", E_WARNING);
            }

            $this->log->script_log("Finished processing compliance");
        }
        else {
            $this->log->script_log("Performing regular check");
            if ($this->debug) {
                $this->log->script_log("{$this->plugin->id}\tPerforming regular check", E_DEBUG);
            }
            if ($this->plugin->sev == 0) {
                return;
            }
            if (false) {
                $this->plugin->result = new nessus_result();
            }
            $finding = $this->db->get_Finding($this->tgt, $this->plugin->db_plugin);

            if (is_array($finding) && count($finding)) {
                $finding = $finding[0];
            }

            if (is_a($finding, 'finding')) {
                $this->log->script_log("Updating finding");
                if (false) {
                    $finding = new finding();
                }
                if ($this->debug) {
                    $this->log->script_log("Finding exists: " . print_r($finding, true), E_DEBUG);
                }

                $orig_scan = $this->db->get_ScanData($this->ste_id, $finding->get_Scan_ID());
                //$orig_src = $this->db->get_Sources($orig_scan->get_Source()->get_ID());
                if ($this->debug) {
                    $this->log->script_log("Previous scan: " . print_r($orig_scan, true), E_DEBUG);
                }

                if (is_array($orig_scan) && count($orig_scan)) {
                    $orig_scan = $orig_scan[0];
                    if (false) {
                        $orig_scan = new scan();
                    }

                    $finding->set_Original_Source($orig_scan->get_Source()->get_Name());
                    $finding->set_Scan_ID($this->scan->get_ID());
                    $finding->set_Finding_Status_By_String(
                        $finding->get_Deconflicted_Status($this->plugin->result->status)
                    );
                    $finding->set_Finding_Iteration($finding->get_Finding_Iteration() + 1);
                    $finding->append_Notes($note);

                    $pdi_id = $finding->get_PDI_ID();

                    if (isset($this->updated_findings[$pdi_id])) {
                        $this->updated_findings[$pdi_id]->append_Notes($note);
                        $this->updated_findings[$pdi_id]->set_Finding_Status_By_String(
                            $this->updated_findings[$pdi_id]->get_Deconflicted_Status($this->plugin->result->status)
                        );
                        $this->updated_findings[$pdi_id]->set_Scan_ID($this->scan->get_ID());
                        $this->updated_findings[$pdi_id]->inc_Finding_Count();
                    }
                }
                else {
                    $this->updated_findings[$finding->get_PDI_ID()] = $finding;
                }

                $this->log->script_log("Finding updated");
                if ($this->debug) {
                    $this->log->script_log("Updated finding: " . print_r($finding, true), E_DEBUG);
                }
            }
            else {
                $this->log->script_log("Adding new finding");
                $tmp = new finding(null, $this->tgt->get_ID(), $this->plugin->db_plugin->get_PDI_ID(), $this->scan->get_ID(), $this->plugin->result->status, $note, finding::NC, "Nessus", 1);
                $tmp->set_Category($this->plugin->result->cat);

                $this->new_findings[$tmp->get_PDI_ID()] = $tmp;
            }

            if (isset($this->plugin->refs['cve']) && is_array($this->plugin->refs['cve']) && count($this->plugin->refs['cve'])) {
                if ($this->debug) {
                    $this->log->script_log("Found " . count($this->plugin->refs['cve']) . " CVE references", E_DEBUG);
                }

                foreach ($this->plugin->refs['cve'] as $ref) {
                    if ($this->debug) {
                        $this->log->script_log("Adding CVE ref $ref to plugin", E_DEBUG);
                    }
                    if (!$this->plugin->db_plugin->ref_Found('cve', $ref)) {
                        $this->plugin->db_plugin->add_Reference('cve', $ref);
                    }
                }
            }

            if (isset($this->plugin->refs['bid']) && is_array($this->plugin->refs['bid']) && count($this->plugin->refs['bid'])) {
                if ($this->debug) {
                    $this->log->script_log("Found " . count($this->plugin->refs['bid']) . " BID references", E_DEBUG);
                }

                foreach ($this->plugin->refs['bid'] as $ref) {
                    if ($this->debug) {
                        $this->log->script_log("Adding BID ref $ref to plugin", E_DEBUG);
                    }
                    if (!$this->plugin->db_plugin->ref_Found('bid', $ref)) {
                        $this->plugin->db_plugin->add_Reference('bid', $ref);
                    }
                }
            }

            if (isset($this->plugin->refs['osvdb']) && count($this->plugin->refs['osvdb'])) {
                if ($this->debug) {
                    $this->log->script_log("Found " . count($this->plugin->refs['osvdb']) . " OSVDB references", E_DEBUG);
                }

                foreach ($this->plugin->refs['osvdb'] as $ref) {
                    if ($this->debug) {
                        $this->log->script_log("Adding OSVDB ref $ref to plugin", E_DEBUG);
                    }
                    if (!$this->plugin->db_plugin->ref_Found('osvdb', $ref)) {
                        $this->plugin->db_plugin->add_Reference('osvdb', $ref);
                    }
                }
            }

            if ($this->debug) {
                $this->log->script_log("Saving {$this->plugin->db_plugin->get_Nessus_ID()}", E_DEBUG);
            }
            $this->db->save_Nessus($this->plugin->db_plugin);
            $this->log->script_log("Finished processing regular check for plugin " . $this->plugin->id);
        }

        // update status
        $this->plugin->chk = null;

        $this->log->script_log("ReportItem_end-END: " . $this->plugin->id);
    }

    function NessusClientData_v2_Report_ReportHost_end()
    {
        $this->log->script_log("ReportHost_end-START: {$this->tgt->get_Name()}");
        // save findings
        $this->tgt->set_PP_flag(true);
        $this->db->save_Target($this->tgt, false);

        $this->log->script_log("Added finding counts: " . count($this->new_findings) . " for target " . $this->tgt->get_Name());
        $this->log->script_log("Updated finding counts: " . count($this->updated_findings) . " for target " . $this->tgt->get_Name());

        $this->log->script_log("Starting to add findings for target");
        $this->db->add_Findings_By_Target($this->updated_findings, $this->new_findings);
        $this->log->script_log("Finished adding findings");

        $this->updated_findings = [];
        $this->new_findings     = [];

        $hl               = new host_list();
        $hl->setTargetId($this->tgt->get_ID());
        $hl->setTargetName($this->tgt->get_Name());
        $hl->setTargetIp($this->host->ip);
        $hl->setFindingCount($this->tgt_finding_count);
        $hl->setScanError($this->host_scan_error);
        $hl->setScanNotes($this->host_scan_notes);

        $this->scan->add_Target_to_Host_List($hl);
        $this->db->update_Running_Scan(basename($this->file), ["name" => "last_host", "value" => $this->tgt->get_Name()]);
        $this->log->script_log("End of host " . $this->tgt->get_Name());

        $this->log->script_log("ReportHost_end-END: " . $this->tgt->get_Name());
    }

    function NessusClientData_v2_Report_end()
    {
        $this->log->script_log("Saving host list");
        $this->db->update_Scan_Host_List($this->scan);

        $this->db->post_Processing();
    }
}

/**
 * The details of the target nessus found
 */
class nessus_target
{

    /**
     * IP Address of the target
     *
     * @var string
     */
    var $ip;

    /**
     * What type of target is this
     *
     * @var string
     */
    var $type;

    /**
     * The operating system string
     *
     * @var string
     */
    var $os_string;

    /**
     * The OS specifics
     *
     * @var software
     */
    var $os;

    /**
     * The login used to access the target
     *
     * @var string
     */
    var $login;

    /**
     * The hostname of the target
     *
     * @var string
     */
    var $hostname;

    /**
     * The full-qualified domain name
     *
     * @var string
     */
    var $fqdn;

    /**
     * The MAC address of the target
     *
     * @var string
     */
    var $mac;

    /**
     * Interface used by nessus to access the target
     *
     * @var interfaces
     */
    var $interface;

    /**
     * Array of open ports or established connections
     *
     * @var array:string
     */
    var $netstat = [];

    /**
     * Array of CPEs found on the target
     *
     * @var array:string
     */
    var $cpes = [];

    /**
     * Array of missing patches
     *
     * @var array:string
     */
    var $missing_patches = [];

}

/**
 * The port info from the finding
 */
class port_info
{

    var $port_num;
    var $proto;
    var $status;
    var $svc_name;

}

/**
 * Specifics of the plugin
 */
class nessus_plugin
{

    /**
     * Nessus plugin ID
     *
     * @var integer
     */
    var $id;

    /**
     * The nessus object
     *
     * @var nessus
     */
    var $db_plugin;

    /**
     * The port number that the nessus plugin is evaulating (not always used)
     *
     * @var integer
     */
    var $port;

    /**
     * The name of the plugin
     *
     * @var string
     */
    var $name;

    /**
     * The service name
     *
     * @var string
     */
    var $svc_name;

    /**
     * The protocol used (TCP/UDP)
     *
     * @var string
     */
    var $proto;

    /**
     * The severity of the vulnerability
     *
     * @var integer
     */
    var $sev;

    /**
     * The family of vulnerabilities
     *
     * @var string
     */
    var $family;

    /**
     * The file name of the nessus plugin (.nasl or .nbin)
     *
     * @var string
     */
    var $fname;

    /**
     * The publication date of the plugin
     *
     * @var DateTime
     */
    var $pub_date;

    /**
     * The date of last modification of the plugin
     *
     * @var DateTime
     */
    var $mod_date;

    /**
     * The description of the plugin
     *
     * @var string
     */
    var $desc;

    /**
     * The type of plugin
     *
     * @var string
     */
    var $type;

    /**
     * A plugin synopsis
     *
     * @var string
     */
    var $synopsis;

    /**
     * The published solution to fix the vulnerability
     *
     * @var string
     */
    var $solution;

    /**
     * Certain risk factors of the vulnerability
     *
     * @var string
     */
    var $risk_factor;

    /**
     * The version of the plugin script
     *
     * @var float
     */
    var $script_ver;

    /**
     * A link to more details for the plugin and vulnerability
     *
     * @var string
     */
    var $see_also;

    /**
     * Array of references for the plugin
     *
     * @var array
     */
    var $refs = [];

    /**
     * The results of the checklist
     *
     * @var nessus_result|compliance
     */
    var $result;

    /**
     * The checklists associated with this plugin
     *
     * @var array:checklist
     */
    var $chk;

    /**
     * The base CVSS score
     *
     * @var float
     */
    var $cvss_base;

    /**
     * The calculated CVSS score
     *
     * @var float
     */
    var $cvss_vector;

}

/**
 * The results of the nessus plugin
 */
class nessus_result
{

    /**
     * The overall status of the vulnerability
     *
     * @var string
     */
    var $status;

    /**
     * Should the status be overridden
     *
     * @var boolean
     */
    var $status_override = false;

    /**
     * The plugin output contents
     *
     * @var string
     */
    var $plugin_output;

    /**
     * The notes contents
     *
     * @var string
     */
    var $notes;

    /**
     * The short title
     *
     * @var string
     */
    var $short_title;

    /**
     * The category/severity of vulnerability
     *
     * @var string
     */
    var $cat;

    /**
     * Constructor
     */
    function __construct()
    {
        $this->status        = 'Not Reviewed';
        $this->plugin_output = '';
    }
}

/**
 * Specifics if this is a compliance scan
 */
class compliance extends nessus_result
{

    /**
     * The STIG id of the finding
     *
     * @var string
     */
    var $stig;

    /**
     * The SV Rule of the finding
     *
     * @var string
     */
    var $sv_rule;

    /**
     * The VMS ID of the finding
     *
     * @var string
     */
    var $vms;

    /**
     * The checklist
     *
     * @var checklist
     */
    var $checklist;

    /**
     * The description of the finding
     *
     * @var string
     */
    var $desc;

    /**
     * The check contents of the finding
     *
     * @var string
     */
    var $check_content;

    /**
     * The CCE ID of the finding
     *
     * @var string
     */
    var $cce;

    /**
     * The available OVAL ID
     *
     * @var string
     */
    var $oval_id;

    /**
     * The DISA IA control under DIACAP
     *
     * @var string
     */
    var $ia_controls;

    /**
     * The audit file used to find this vulnerability
     *
     * @var string
     */
    var $audit_file;

    /**
     * The CCI ID of the finding (if applicable)
     *
     * @var string
     */
    var $cci;

    /**
     * How to fix the finding and bring it into compliance
     *
     * @var string
     */
    var $solution;

    /**
     *
     *
     * @var string
     */
    var $file;

    /**
     * What the actual value of the setting is
     *
     * @var string
     */
    var $actual_value;

    /**
     * What the STIG policy says the value is supposed to be
     *
     * @var string
     */
    var $policy_value;

}

$xml        = new nessus_parser($conf['ste'], $cmd['f']);
$xml->debug = (isset($cmd['debug']) || LOG_LEVEL == E_DEBUG ? true : false);
//Enter xml code here
$xml->parse();

/**
 * Function to parse the content of plugin 10107
 *
 * @param nessus_parser $parser
 */
function n10107(&$parser)
{
    update_Port_Banner($parser);
}

/**
 * Function to parse the content of plugin 10144
 *
 * @todo fix
 *
 * @param nessus_parser $parser
 */
function n10144(&$parser)
{

    return;
    $match = [];
    $ver   = '0';
    if (preg_match("/([\d\.?]+)/", $parser->plugin->result->plugin_output, $match)) {
        $ver = $match[1];
    }
    /* @TODO - FIX! */
    //$sw = software::toSoftwareFromArray(array('man'=>'microsoft','name'=>'sql server','ver'=>$ver,'type'=>false));
    $sw = $parser->db->get_Software("cpe:/a:microsoft:sql_server:$ver");
    if (is_array($sw) && count($sw)) {
        $sw = $sw[0];
    }
    else {
        //$sw = software::toSoftwareFromArray(array('man'=>'microsoft','name'=>'sql server','ver'=>$ver,'type'=>false));
        $sw_id = $parser->db->save_Software("cpe:/a:microsoft:sql_server:$ver");
        $sw->set_ID($sw_id);
    }

    $parser->tgt->software[] = $sw;
}

/**
 * Function to parse the content of plugin 10158
 *
 * @param nessus_parser $parser
 */
function n10158(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10185
 *
 * @param nessus_parser $parser
 */
function n10185(&$parser)
{
    update_Port_Banner($parser);
}

/**
 * Function to parse the content of plugin 10264
 *
 * @param nessus_parser $parser
 */
function n10264(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10267
 *
 * @param nessus_parser $parser
 */
function n10267(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10287
 *
 * @param nessus_parser $parser
 */
function n10287(&$parser)
{
    if (!empty($parser->host->ip)) {
        $parser->tgt->interfaces[$parser->host->ip]->set_Notes($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10395
 *
 * @param nessus_parser $parser
 */
function n10395(&$parser)
{
    if (strlen($parser->tgt->get_Shares()) > 0) {
        $parser->tgt->set_Shares($parser->tgt->get_Shares() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Shares($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10396
 *
 * @param nessus_parser $parser
 */
function n10396(&$parser)
{
    if (strlen($parser->tgt->get_Shares()) > 0) {
        $parser->tgt->set_Shares($parser->tgt->get_Shares() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Shares($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10437
 *
 * @param nessus_parser $parser
 */
function n10437(&$parser)
{
    if (strlen($parser->tgt->get_Shares()) > 0) {
        $parser->tgt->set_Shares($parser->tgt->get_Shares() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Shares($parser->plugin->result->plugin_output);
    }

    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10456
 *
 * @param nessus_parser $parser
 */
function n10456(&$parser)
{
    if (strlen($parser->tgt->get_Services()) > 0) {
        $parser->tgt->set_Services($parser->tgt->get_Services() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Services($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10546
 *
 * @param nessus_parser $parser
 */
function n10546(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10547
 *
 * @param nessus_parser $parser
 */
function n10547(&$parser)
{
    if (strlen($parser->tgt->get_Services()) > 0) {
        $parser->tgt->set_Services($parser->tgt->get_Services() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Services($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10550
 *
 * @param nessus_parser $parser
 */
function n10550(&$parser)
{
    if (strlen($parser->tgt->get_Process_List()) > 0) {
        $parser->tgt->set_Process_List($parser->tgt->get_Process_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Process_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10551
 *
 * @param nessus_parser $parser
 */
function n10551(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10736
 *
 * @param nessus_parser $parser
 */
function n10736(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10800
 *
 * @param nessus_parser $parser
 */
function n10800(&$parser)
{
    $parser->tgt->set_System($parser->plugin->result->plugin_output);

    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10874
 *
 * @param nessus_parser $parser
 */
function n10874(&$parser)
{
    update_Port_Banner($parser);
}

/**
 * Function to parse the content of plugin 10884
 *
 * @param nessus_parser $parser
 */
function n10884(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 10902
 *
 * @param nessus_parser $parser
 */
function n10902(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10904
 *
 * @param nessus_parser $parser
 */
function n10904(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10905
 *
 * @param nessus_parser $parser
 */
function n10905(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10906
 *
 * @param nessus_parser $parser
 */
function n10906(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10913
 *
 * @param nessus_parser $parser
 */
function n10913(&$parser)
{
    if (strlen($parser->tgt->get_Disabled_Accts()) > 0) {
        $parser->tgt->set_Disabled_Accts($parser->tgt->get_Disabled_Accts() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Disabled_Accts($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10914
 *
 * @param nessus_parser $parser
 */
function n10914(&$parser)
{
    if (strlen($parser->tgt->get_Stag_Pwds()) > 0) {
        $parser->tgt->set_Stag_Pwds($parser->tgt->get_Stag_Pwds() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Stag_Pwds($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10915
 *
 * @param nessus_parser $parser
 */
function n10915(&$parser)
{
    if (strlen($parser->tgt->get_Never_Logged_In()) > 0) {
        $parser->tgt->set_Never_Logged_In($parser->tgt->get_Never_Logged_In() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Never_Logged_In($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 10916
 *
 * @param nessus_parser $parser
 */
function n10916(&$parser)
{
    if (strlen($parser->tgt->get_Pwds_Never_Expire()) > 0) {
        $parser->tgt->set_Pwds_Never_Expire($parser->tgt->get_Pwds_Never_Expire() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Pwds_Never_Expire($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 11111
 *
 * @param nessus_parser $parser
 */
function n11111(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 11219
 *
 * @param nessus_parser $parser
 */
function n11219(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 11777
 *
 * @param nessus_parser $parser
 */
function n11777(&$parser)
{
    $parser->tgt->set_Copyright($parser->plugin->result->plugin_output);
}

/**
 * Function to parse the content of plugin 12634
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n12634(&$parser)
{
    $os = $parser->db->get_Software($parser->tgt->get_OS_ID());
    if (!empty($os)) {
        $os = $os[0];
    }
    else {
        return;
    }

    // parse results and put in proper place
    //if($os->get_SP() != $parser->plugin->result->plugin_output);
}

/**
 * Function to parse the content of plugin 19506
 *
 * @param nessus_parser $parser
 */
function n19506(&$parser)
{
    $parser->scan->set_Notes($parser->plugin->result->plugin_output);
}

/**
 * Function to parse the content of plugin 19763
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n19763(&$parser)
{
    $sw_arr = explode("\n", $parser->plugin->result->plugin_output);

    foreach ($sw_arr as $key => $sw) {

    }
}

/**
 * Function to parse the content of plugin 20094
 *
 * @param nessus_parser $parser
 */
function n20094(&$parser)
{
    $parser->tgt->set_VM(true);
}

/**
 * Function to parse the content of plugin 20148
 *
 * @param nessus_parser $parser
 */
function n20148(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 20811
 *
 * @param nessus_parser $parser
 */
function n20811(&$parser)
{
    $sw_arr   = explode(PHP_EOL, $parser->plugin->result->plugin_output);
    $ms_regex = $parser->db->get_Regex_Array("ms");

    return;

    for ($x = 3; $x < count($sw_arr) - 1; $x++) {
        if (empty($sw_arr[$x])) {
            $x = count($sw_arr);
            break;
        }
        if (preg_match("/outlook web access|security update|nvidia|visio viewer/i", $sw_arr[$x])) {
            continue;
        }
        //$sw = what_software($sw_arr[$x]);
        $sw = software::identify_Software($ms_regex, $sw_arr[$x], true);
        if ($parser->debug) {
            $parser->log->script_log("Identified {$sw_arr[0]} as " . print_r($sw, true), E_DEBUG);
        }

        if (count($sw)) {
            $sw    = $sw[0];
            $db_sw = $parser->db->get_Software($sw->get_CPE());
            if (count($db_sw)) {
                if (!in_array($db_sw[0], $parser->tgt->software)) {
                    if ($parser->debug) {
                        $parser->log->script_log("Adding {$db_sw[0]->get_Name()} to {$parser->tgt->get_Name()}", E_DEBUG);
                    }
                    $parser->tgt->software[] = $db_sw[0];
                }
            }
        }
    }
}

/**
 * Function to parse the content of plugin 21745
 *
 * @param nessus_parser $parser
 */
function n21745(&$parser)
{
    $parser->host_scan_error = true;
    $parser->host_scan_notes = "Authentication failure: " . $parser->plugin->result->plugin_output;
    //$parser->tgt->set_Notes("Authentication failure: " . $parser->plugin->result->plugin_output);
}

/**
 * Function to parse the content of plugin 22869
 *
 * @param nessus_parser $parser
 */
function n22869(&$parser)
{
    $sw_arr    = explode(PHP_EOL, $parser->plugin->result->plugin_output);
    $nix_regex = $parser->db->get_Regex_Array("nix");

    for ($x = 3; $x < count($sw_arr) - 1; $x++) {
        //$sw = what_software($sw_arr[$x]);
        $sw = software::identify_Software($nix_regex, $sw_arr[$x], true);

        if (is_array($sw) && count($sw)) {
            $sw    = $sw[0];
            $db_sw = $parser->db->get_Software($sw->get_CPE());
            if (is_array($db_sw) && count($db_sw)) {
                if (!in_array($db_sw[0], $parser->tgt->software)) {
                    $parser->tgt->software[] = $db_sw[0];
                }
            }
        }
    }
}

/**
 * Function to parse the content of plugin 22964
 *
 * @param nessus_parser $parser
 */
function n22964(&$parser)
{
    update_Port_Banner($parser);
}

/**
 * Function to parse the content of plugin 24260
 *
 * @param nessus_parser $parser
 */
function n24260(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 24270
 *
 * @param nessus_parser $parser
 */
function n24270(&$parser)
{
    if (strlen($parser->tgt->get_System()) > 0) {
        $parser->tgt->set_System($parser->tgt->get_System() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_System($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 24272
 *
 * @param nessus_parser $parser
 */
function n24272(&$parser)
{

    $arr = explode(PHP_EOL, $parser->plugin->result->plugin_output);

    $name  = '';
    $mac   = '';
    $ipv4  = '';
    $ipv6  = '';
    $match = [];

    foreach ($arr as $line) {
        if (preg_match("/Routing Information/i", $line)) {
            break;
        }

        switch ($line) {
            case (preg_match("/Network Interface Information/i", $line) ? true : false):
                if ($name && $mac && $ipv4) {
                    if (!isset($parser->tgt->interfaces[$ipv4])) {
                        $parser->tgt->interfaces[$ipv4] = new interfaces(null, $parser->tgt->get_ID(), $name, $ipv4, null, $parser->host->hostname, $parser->host->fqdn, null);
                    }
                }
                if ($name && $mac && $ipv6) {
                    if (!isset($parser->tgt->interfaces[$ipv6])) {
                        $parser->tgt->interfaces[$ipv6] = new interfaces(null, $parser->tgt->get_ID(), $name, null, $ipv6, $parser->host->hostname, $parser->host->fqdn, null);
                    }
                }
                $name = '';
                $mac  = '';
                $ipv4 = '';
                $ipv6 = '';
                break;
            case (preg_match("/Network Interface \= (.*)/i", $line, $match) ? true : false):
                $name = $match[1];
                break;
            case (preg_match("/MAC Address \= ([\d\:]+)/i", $line, $match) ? true : false):
                $mac  = $match[1];
                break;
            case (preg_match("/IPAddress\/IPSubnet \= ([\d\.]+)\/([\d\.]+)/i", $line, $match) ? true : false):
                $ipv4 = $match[1];
                break;
            case (preg_match("/IPAddress\/IPSubnet \= ([a-f\d\:]+)\/([\d]+)/i", $line, $match) ? true : false):
                $ipv6 = $match[1];
                break;
        }
    }
}

/**
 * Function to parse the content of plugin 24745
 *
 * @param nessus_parser $parser
 */
function n24745(&$parser)
{
    if (strlen($parser->tgt->get_Notes())) {
        $parser->tgt->set_Notes($parser->plugin->synopsis . PHP_EOL . $parser->tgt->get_Notes());
    }
    else {
        $parser->tgt->set_Notes($parser->plugin->synopsis);
    }
}

/**
 * Function to parse the content of plugin 25202
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n25202(&$parser)
{

}

/**
 * Function to parse the content of plugin 25203
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n25203(&$parser)
{

}

/**
 * Function to parse the content of plugin 25221
 *
 * @param nessus_parser $parser
 */
function n25221(&$parser)
{
    if (strlen($parser->tgt->get_Process_List()) > 0) {
        $parser->tgt->set_Process_List($parser->tgt->get_Process_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Process_List($parser->plugin->result->plugin_output);
    }

    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 26921
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n26921(&$parser)
{

}

/**
 * Function to parse the content of plugin 29217
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n29217(&$parser)
{

}

/**
 * Function to parse the content of plugin 34022
 *
 * @param nessus_parser $parser
 */
function n34022(&$parser)
{

    if (strlen($parser->tgt->get_Routes()) > 0) {
        $parser->tgt->set_Routes($parser->tgt->get_Routes() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Routes($parser->plugin->result->plugin_output);
    }

    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 34096
 *
 * @param nessus_parser $parser
 */
function n34096(&$parser)
{

    if (strlen($parser->tgt->get_BIOS()) > 0) {
        $parser->tgt->set_BIOS($parser->tgt->get_BIOS() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_BIOS($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 34098
 *
 * @param nessus_parser $parser
 */
function n34098(&$parser)
{

    if (strlen($parser->tgt->get_BIOS()) > 0) {
        $parser->tgt->set_BIOS($parser->tgt->get_BIOS() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_BIOS($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 34252
 *
 * @param nessus_parser $parser
 */
function n34252(&$parser)
{
    $match = [];

    if (preg_match("/\(pid ([\d]+)\)/", $parser->plugin->result->plugin_output, $match)) {
        $parser->tgt->set_WMI_PID($match[1]);
    }
}

/**
 * Function to parse the content of plugin 35296
 *
 * @param nessus_parser $parser
 */
function n35296(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 35716
 *
 * @param nessus_parser $parser
 */
function n35716(&$parser)
{

}

/**
 * Function to parse the content of plugin 38153
 *
 * @param nessus_parser $parser
 *
 * @todo - fix
 */
function n38153(&$parser)
{
    $parser->tgt->set_Missing_Patches($parser->tgt->get_Missing_Patches() . PHP_EOL . $parser->plugin->result->plugin_output);

    return;
    /*
     * Main section removed because it takes entirely too long.  Need to revise operation after release
     */
    $match = [];
    $lines = explode(PHP_EOL, $parser->plugin->result->plugin_output);
    for ($x = 2; $x < count($lines) - 1; $x++) {
        if (preg_match("/ \- ([a-zA-Z0-9\-]+)/i", $lines[$x], $match)) {
            $iavm = $parser->db->get_IAVM_From_External($match[1]);
            if (!empty($iavm)) {
                // add finding
            }
            else {
                $cve = $parser->db->get_CVE_From_External($match[1]);
                if (!empty($cve)) {

                }
            }
        }
    }
}

/**
 * Function to parse the content of plugin 38689
 *
 * @param nessus_parser $parser
 */
function n38689(&$parser)
{
    $match = [];
    if (preg_match("/Last Successful logon \: (.*)\n/i", $parser->plugin->result->plugin_output, $match)) {
        $parser->tgt->set_Last_Login($match[1]);
    }
}

/**
 * Function to parse the content of plugin 40448
 *
 * @param nessus_parser $parser
 */
function n40448(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 41028
 *
 * @param nessus_parser $parser
 */
function n41028(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 42799
 *
 * @param nessus_parser $parser
 */
function n42799(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 43069
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n43069(&$parser)
{

}

/**
 * Function to parse the content of plugin 43111
 *
 * @param nessus_parser $parser
 */
function n43111(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 44401
 *
 * @param nessus_parser $parser
 */
function n44401(&$parser)
{

    if (strlen($parser->tgt->get_Services()) > 0) {
        $parser->tgt->set_Services($parser->tgt->get_Services() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Services($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 45590
 *
 * @todo loop through to get better resolution on installed software once CPE's are running
 *    Partially complete
 *
 * @param nessus_parser $parser
 */
function n45590(&$parser)
{
    return;
    // this is a duplicate of the <tag name="cpe-\d"> in the host properties section, may remove since parsing CPE in host properties
    $match = [];

    if (preg_match("/(cpe\:\/o[^\s]+)/", $parser->plugin->result->plugin_output, $match)) {
        $os_cpe = $match[1];

        $os = $parser->db->get_Software($os_cpe, true);
        if (is_array($os) && count($os)) {
            if ($os[0]->get_ID() != $parser->tgt->get_OS_ID()) {
                $parser->tgt->set_OS_ID($os[0]->get_ID());
                $parser->log->script_log("Enhancing OS detection with " . $os[0]->get_Man() . " " . $os[0]->get_Name() . " " . $os[0]->get_Version);
            }
        }
    }

    $cpes = explode(PHP_EOL, $parser->plugin->result->plugin_output);
    $cpes = array_values(preg_grep("/cpe\:\/a/i", $cpes));

    if (is_array($cpes) && count($cpes)) {
        foreach ($cpes as $cpe) {
            $cpe = preg_replace("/(cpe\:[^\s]+)/", "$1", $cpe);

            $sw = $parser->db->get_Software($cpe, true);
            if (is_array($sw) && count($sw)) {
                if (!in_array($sw[0], $parser->tgt->software)) {
                    $parser->tgt->software[] = $sw[0];
                    $parser->log->script_log("Adding software " . $sw[0]->get_Man() . " " . $sw[0]->get_Name() . " " . $sw[0]->get_Version());
                }
            }
        }
    }
}

/**
 * Function to parse the content of plugin 46742
 *
 * @param nessus_parser $parser
 */
function n46742(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 48337
 *
 * @param nessus_parser $parser
 */
function n48337(&$parser)
{

    if (strlen($parser->tgt->get_System()) > 0) {
        $parser->tgt->set_System($parser->tgt->get_System() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_System($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 48942
 *
 * @param nessus_parser $parser
 */
function n48942(&$parser)
{
    $match = [];
    $ver   = '';
    $arch  = '';

    if (preg_match("/Operating System Version \= ([\d\.]+)/", $parser->plugin->result->plugin_output, $match)) {
        $ver = $match[1];
    }

    if (preg_match("/Architecture \= ([x\d]+)/", $parser->plugin->result->plugin_output, $match)) {
        $arch = $match[1];
    }

    // @todo Add fidelity to CPE if available
}

/**
 * Function to parse the content of plugin 52001
 *
 * @todo finish
 *
 * @param nessus_parser $parser
 */
function n52001(&$parser)
{
    $match = [];
    if (preg_match("/\+ KB([\d]+)/", $parser->plugin->result->plugin_output, $match)) {
        $iavm = $parser->db->get_IAVM_From_External("KB" . $match[1]);

        if (!empty($iavm)) {
            // add finding
        }
        else {
            $cve = $parser->db->get_CVE_From_External("KB" . $match[1]);

            if (!empty($cve)) {
                // get linked IAVM and add finding if available
            }
        }
    }
}

/**
 * Function to parse the content of plugin 52459
 *
 * @param nessus_parser $parser
 */
function n52459(&$parser)
{

}

/**
 * Function to parse the content of plugin 53360
 *
 * @param nessus_parser $parser
 */
function n53360(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 56310
 *
 * @param nessus_parser $parser
 */
function n56310(&$parser)
{
    if (strlen($parser->tgt->get_Firewall_Config()) > 0) {
        $parser->tgt->set_Firewall_Config($parser->tgt->get_Firewall_Config() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Firewall_Config($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 56468
 *
 * @param nessus_parser $parser
 */
function n56468(&$parser)
{
    $match = [];
    if (preg_match("/([\d]{14}[\d\.\-]+)/", $parser->plugin->result->plugin_output, $match)) {
        $dt = DateTime::createFromFormat("YmdHis.uO", $match[1]);
        $parser->tgt->set_Last_Boot($dt);
    }
    elseif (preg_match("/^\n  reboot   system boot  [\d\.\-a-z]+ (.*) \-.*   $/m", $parser->plugin->result->plugin_output, $match)) {
        $dt = DateTime::createFromFormat("D M j H:i", $match[1]);
        $parser->tgt->set_Last_Boot($dt);
    }
    elseif (preg_match("/^\n\s+reboot\s+system boot\s+(.*) $/", $parser->plugin->result->plugin_output, $match)) {
        $dt = DateTime::createFromFormat("D M j H:i", $match[1]);
        $parser->tgt->set_Last_Boot($dt);
    }
}

/**
 * Function to parse the content of plugin 58452
 *
 * @param nessus_parser $parser
 */
function n58452(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 58651
 *
 * @param nessus_parser $parser
 */
function n58651(&$parser)
{
    $parser->tgt->set_Netstat_Connections($parser->plugin->result->plugin_output);
}

/**
 * Function to parse the content of plugin 63080
 *
 * @param nessus_parser $parser
 */
function n63080(&$parser)
{
    if (strlen($parser->tgt->get_Mounted()) > 0) {
        $parser->tgt->set_Mounted($parser->tgt->get_Mounted() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Mounted($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 63620
 *
 * @param nessus_parser $parser
 */
function n63620(&$parser)
{
    $match = [];
    if (preg_match("/Product key \: (.*)/", $parser->plugin->result->plugin_output, $match)) {
        // @todo going to have to redo this and assign software per host and add product key to that
    }
}

/**
 * Function to parse the content of plugin 66334
 *
 * @param nessus_parser $parser
 */
function n66334(&$parser)
{
    $parser->tgt->set_Missing_Patches($parser->plugin->result->plugin_output);
}

/**
 * Function to parse the content of plugin 70329
 *
 * @param nessus_parser $parser
 */
function n70329(&$parser)
{
    if (strlen($parser->tgt->get_Process_List()) > 0) {
        $parser->tgt->set_Process_List($parser->tgt->get_Process_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Process_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70330
 *
 * @param nessus_parser $parser
 */
function n70330(&$parser)
{
    if (empty($parser->tgt)) {
        return;
    }

    if (strlen($parser->tgt->get_Process_List()) > 0) {
        $parser->tgt->set_Process_List($parser->tgt->get_Process_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Process_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70613
 *
 * @param nessus_parser $parser
 */
function n70613(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70615
 *
 * @param nessus_parser $parser
 */
function n70615(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70616
 *
 * @param nessus_parser $parser
 */
function n70616(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70917
 *
 * @param nessus_parser $parser
 */
function n70617(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70618
 *
 * @param nessus_parser $parser
 */
function n70618(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70619
 *
 * @param nessus_parser $parser
 */
function n70619(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70620
 *
 * @param nessus_parser $parser
 */
function n70620(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70621
 *
 * @param nessus_parser $parser
 */
function n70621(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70622
 *
 * @param nessus_parser $parser
 */
function n70622(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70623
 *
 * @param nessus_parser $parser
 */
function n70623(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70624
 *
 * @param nessus_parser $parser
 */
function n70624(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70625
 *
 * @param nessus_parser $parser
 */
function n70625(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70626
 *
 * @param nessus_parser $parser
 */
function n70626(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70628
 *
 * @param nessus_parser $parser
 */
function n70628(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70629
 *
 * @param nessus_parser $parser
 */
function n70629(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70630
 *
 * @param nessus_parser $parser
 */
function n70630(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 70657
 *
 * @param nessus_parser $parser
 */
function n70657(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 70658
 *
 * @param nessus_parser $parser
 */
function n70658(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 70918
 *
 * @param nessus_parser $parser
 */
function n70918(&$parser)
{
    if (strlen($parser->tgt->get_Autorun()) > 0) {
        $parser->tgt->set_Autorun($parser->tgt->get_Autorun() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_Autorun($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 71049
 *
 * @param nessus_parser $parser
 */
function n71049(&$parser)
{
    update_Port_Notes($parser);
}

/**
 * Function to parse the content of plugin 71246
 *
 * @param nessus_parser $parser
 */
function n71246(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Function to parse the content of plugin 72684
 *
 * @param nessus_parser $parser
 */
function n72684(&$parser)
{
    if (strlen($parser->tgt->get_User_List()) > 0) {
        $parser->tgt->set_User_List($parser->tgt->get_User_List() . PHP_EOL . $parser->plugin->result->plugin_output);
    }
    else {
        $parser->tgt->set_User_List($parser->plugin->result->plugin_output);
    }
}

/**
 * Generic function to update the port notes
 *
 * @param nessus_parser $parser
 */
function update_Port_Notes(&$parser)
{
    if (empty($parser->host->ip)) {
        return;
    }
    if ($parser->plugin->proto == 'tcp') {
        if (isset($parser->tgt->interfaces[$parser->host->ip])) {
            if ($port = $parser->tgt->interfaces[$parser->host->ip]->get_TCP_Port_By_Port_Number($parser->plugin->port)) {
                $port->set_Notes($parser->plugin->result->plugin_output);
                $parser->tgt->interfaces[$parser->host->ip]->update_TCP_Port($port);
            }
            else {
                $port = new tcp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, null, $parser->plugin->result->plugin_output);
                $parser->tgt->interfaces[$parser->host->ip]->add_TCP_Ports($port);
            }
        }
        else {
            $parser->tgt->interfaces[$parser->host->ip] = new interfaces(null, $parser->tgt->get_ID(), null, $parser->host->ip, null, $parser->host->hostname, $parser->host->fqdn, null);
            $port                                       = new tcp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, null, $parser->plugin->result->plugin_output);
            $parser->tgt->interfaces[$parser->host->ip]->add_TCP_Ports($port);
        }
    }
    else {
        if (isset($parser->tgt->interfaces[$parser->host->ip])) {
            if ($port = $parser->tgt->interfaces[$parser->host->ip]->get_UDP_Port_By_Port_Number($parser->plugin->port)) {
                $port->set_Notes($parser->plugin->result->plugin_output);
                $parser->tgt->interfaces[$parser->host->ip]->update_UDP_Port($port);
            }
            else {
                $port = new udp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, null, $parser->plugin->result->plugin_output);
                $parser->tgt->interfaces[$parser->host->ip]->add_UDP_Ports($port);
            }
        }
        else {
            $parser->tgt->interfaces[$parser->host->ip] = new interfaces(null, $parser->tgt->get_ID(), null, $parser->host->ip, null, $parser->host->hostname, $parser->host->fqdn, null);
            $port                                       = new udp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, null, $parser->plugin->result->plugin_output);
            $parser->tgt->interfaces[$parser->host->ip]->add_UDP_Ports($port);
        }
    }
}

/**
 * Generic function to update the port banner
 *
 * @param nessus_parser $parser
 */
function update_Port_Banner(&$parser)
{
    if (empty($parser->host->ip)) {
        return;
    }
    if ($parser->plugin->proto == 'tcp') {
        if (isset($parser->tgt->interfaces[$parser->host->ip])) {
            if ($port = $parser->tgt->interfaces[$parser->host->ip]->get_TCP_Port_By_Port_Number($parser->plugin->port)) {
                $port->set_Banner($parser->plugin->result->plugin_output);
                $parser->tgt->interfaces[$parser->host->ip]->update_TCP_Port($port);
            }
            else {
                $port = new tcp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, $parser->plugin->result->plugin_output, $parser->plugin->solution);
                $parser->tgt->interfaces[$parser->host->ip]->add_TCP_Ports($port);
            }
        }
        else {
            $parser->tgt->interfaces[$parser->host->ip] = new interfaces(null, $parser->tgt->get_ID(), null, $parser->host->ip, null, $parser->host->hostname, $parser->host->fqdn, null);
            $port                                       = new tcp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, $parser->plugin->result->plugin_output, $parser->plugin->solution);
            $parser->tgt->interfaces[$parser->host->ip]->add_TCP_Ports($port);
        }
    }
    else {
        if (isset($parser->tgt->interfaces[$parser->host->ip])) {
            if ($port = $parser->tgt->interfaces[$parser->host->ip]->get_UDP_Port_By_Port_Number($parser->plugin->port)) {
                $port->set_Banner($parser->plugin->result->plugin_output);
                $parser->tgt->interfaces[$parser->host->ip]->update_UDP_Port($port);
            }
            else {
                $port = new udp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, $parser->plugin->result->plugin_output, $parser->plugin->solution);
                $parser->tgt->interfaces[$parser->host->ip]->add_UDP_Ports($port);
            }
        }
        else {
            $parser->tgt->interfaces[$parser->host->ip] = new interfaces(null, $parser->tgt->get_ID(), null, $parser->host->ip, null, $parser->host->hostname, $parser->host->fqdn, null);
            $port                                       = new udp_ports(null, $parser->plugin->port, $parser->plugin->svc_name, $parser->plugin->result->plugin_output, $parser->plugin->solution);
            $parser->tgt->interfaces[$parser->host->ip]->add_UDP_Ports($port);
        }
    }
}

/**
 * Function to print the usage statement to the command-line
 */
function usage()
{
    print <<<EOO
Purpose: To import a Nessus result file

Usage: php parse_nessus.php -s={ST&E ID} -f={Nessus result file} -d={document root} [--debug] [--help]

 -s={ST&E ID}       The ST&E ID this result file is being imported for
 -f={Nessus file}   The result file to import
 -d={document root} The document root of the web server

 --debug            Debugging output
 --help             This screen

EOO;
}
