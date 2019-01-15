<?php

/**
 * File: parse_scc_xccdf.php
 * Author: Ryan Prather
 * Purpose: Background script to parse SCC XCCDF result files
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
 *  - Jun 3, 2015 - Copyright updated, added CWD parameter, and
 * 					updated function calls after class merger
 *  - Oct 24, 2016 - Converted XMLParser to scan_xml_parser class
 *  - Jan 30, 2017 - Updated to use parse_config.ini file
 *  - May 13, 2017 - Fixed error when trying to delete a USGCB scan file (not supported)
 *  - Oct 23, 2017 - Fixed error of finding statuses being overwritten
 */
$cmd = getopt("f:", [
    'debug::',
    'help::'
]);

if (! isset($cmd['f']) || isset($cmd['help'])) {
    die(usage());
}

$conf = parse_ini_file("parse_config.ini");

if (! $conf) {
    die("Could not find parse_config.ini configuration file");
}

chdir($conf['doc_root']);

set_time_limit(0);
require_once 'vendor/autoload.php';
include_once 'config.inc';
include_once 'xml_parser.inc';
include_once 'database.inc';
include_once 'helper.inc';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

chdir(TMP);

$db = new db();

$log_level = convert_log_level();

$base_name = basename($cmd['f']);
$log = new Logger("scc-import");
$log->pushHandler(new StreamHandler(logify($cmd['f']), $log_level));

if (! file_exists($cmd['f'])) {
    $db->update_Running_Scan($base_name, [
        'name' => 'status',
        'value' => 'ERROR'
    ]);
    $log->error("File not found");
    die();
} elseif (preg_match('/.*Results\_iavm\_(2009|2010)|Results\_USGCB/i', $cmd['f'])) {
    $scan = $db->get_ScanData($conf['ste'], $cmd['f']);
    if (is_array($scan) && count($scan) && isset($scan[0]) && is_a($scan[0], 'scan')) {
        $db->delete_Scan($scan[0]->get_ID(), false);
    }
    $log->error("Cannot parse these types of files");
    die();
}

class scc_parser extends scan_xml_parser
{

    var $values;

    var $value_id;

    var $getvalue = false;

    var $groups;

    var $group_id;

    var $vms_id;

    var $vms = null;

    var $sv_rule;

    var $tgt;

    var $tag;

    var $int_count = 0;

    var $found_rule = false;

    /**
     * Constructor
     *
     * @global Monolog\Logger $log
     *
     * @param int $ste_id_in
     * @param string $fname_in
     */
    public function __construct($ste_id_in, $fname_in)
    {
        $this->values = [];
        $this->groups = [];
        $this->tag = [];
        parent::__construct($this, $ste_id_in, $fname_in);
    }
    
    /**
     * Function to parse \cdf:Benchmark
     * 
     * @param array $attrs
     */
    public function cdf_Benchmark($attrs)
    {
        $this->scan->set_Start_Time(new DateTime("now", new DateTimeZone("UTC")));
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Value tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_Value($attrs)
    {
        $this->values[$attrs['id']] = null;
        $this->value_id = $attrs['id'];
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Value\cdf:value tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_Value_cdf_value($attrs)
    {
        $this->getvalue = false;
        if (! isset($attrs['selector'])) {
            $this->getvalue = true;
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:value\cdf:value character data
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_Value_cdf_value_data($data)
    {
        if ($this->getvalue) {
            $this->values[$this->value_id] = $data;
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_Group($attrs)
    {
        $this->found_rule = false;
        $match = [];
        $this->vms_id = null;
        $this->vms = null;

        if(preg_match("/(V\-[\d]+)/", $attrs['id'], $match)) {
            $this->vms_id = $match[1];
            $this->group_id = $this->vms_id;
        }
        else {
            return;
        }
        $this->vms = $this->db->get_GoldDisk($this->vms_id);

        if (is_array($this->vms) && count($this->vms) && isset($this->vms[0]) && is_a($this->vms[0], 'golddisk')) {
            $this->vms = $this->vms[0];
            $this->group_id = $this->vms->get_PDI_ID();
        }

        $this->groups[$this->group_id] = [];
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule($attrs)
    {
        $sv_rule = $this->db->get_SV_Rule(null, $attrs['id']);

        if (is_array($sv_rule) && count($sv_rule) && isset($sv_rule[0]) && is_a($sv_rule[0], 'sv_rule')) {
            $this->found_rule = true;
            $this->sv_rule = $sv_rule[0];

            unset($this->groups[$this->group_id]);
            $this->group_id = $this->sv_rule->get_PDI_ID();

            $this->groups[$this->group_id] = [
                'sv_rule' => $this->sv_rule,
                'stig' => null,
                'version' => null,
                'title' => null,
                'vms_id' => $this->vms_id,
                'oval_id' => null,
                'val_id' => null,
                'value' => null,
                'cce' => null,
                'fix' => null,
                'desc' => null,
                'status' => "Not Reviewed",
                'cat' => 2
            ];
        } else {
            return;
        }

        $stig = $this->db->get_STIG_By_PDI($this->sv_rule->get_PDI_ID());

        if (is_a($stig, 'stig')) {
            $this->groups[$this->group_id]['stig'] = $stig;
            $this->groups[$this->group_id]['version'] = $stig->get_ID();
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule\cdf:version character data (STIG id)
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule_cdf_version_data($data)
    {
        $stig = $this->db->get_Stig($data);
        if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
            $this->found_rule = true;
            $stig = $stig[0];

            unset($this->groups[$this->group_id]);
            $this->group_id = $stig->get_PDI_ID();

            $this->groups[$this->group_id] = [
                'sv_rule' => (is_a($this->sv_rule, 'sv_rule') ? $this->sv_rule : null),
                'stig' => $stig,
                'version' => $stig->get_ID(),
                'title' => null,
                'vms_id' => $this->vms_id,
                'oval_id' => null,
                'val_id' => null,
                'value' => null,
                'cce' => null,
                'fix' => null,
                'desc' => null,
                'status' => "Not Reviewed",
                'cat' => 2
            ];
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule\cdf:title character data (short title)
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule_cdf_title_data($data)
    {
        if (empty($this->groups[$this->group_id]['title'])) {
            $this->groups[$this->group_id]['title'] = $data;
        } else {
            // error_log(print_r($this->group_id, true));
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule\cdf:description character data (description)
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule_cdf_description_data($data)
    {
        if (! isset($this->groups[$this->group_id])) {
            $this->groups[$this->group_id] = [];
        }

        if (isset($this->groups[$this->group_id]['desc'])) {
            $this->groups[$this->group_id]['desc'] .= $data;
        } else {
            $this->groups[$this->group_id]['desc'] = $data;
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule\cdf:ident character data (CCI,CCE,etc)
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule_cdf_ident_data($data)
    {
        if (empty($this->groups[$this->group_id]['cce']) && preg_match("/CCE/", $data)) {
            $this->groups[$this->group_id]['cce'] = $data;
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule\cdf:fixtext character data
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule_cdf_fixtext_data($data)
    {
        if (empty($this->groups[$this->group_id]['fix'])) {
            $this->groups[$this->group_id]['fix'] = htmlentities($data);
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group\cdf:Rule\cdf:check\cdf:check-export tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_Group_cdf_Rule_cdf_check_cdf_check_export($attrs)
    {
        if (empty($this->groups[$this->group_id]['val_id'])) {
            $this->groups[$this->group_id]['val_id'] = $attrs['value-id'];
            $this->groups[$this->group_id]['value'] = $this->values[$attrs['value-id']];

            $this->groups[$this->group_id]['oval_id'] = $attrs['export-name'];
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:Group end tag and store content parsed from previous functions
     */
    public function cdf_Benchmark_cdf_Group_end()
    {
        if (! $this->found_rule) {
            $this->log->script_log("Rule tag was not present for " . $this->group_id);
            unset($this->groups[$this->group_id]);
            return;
        }

        if (empty($this->groups[$this->group_id]['stig'])) {
            $ia_controls = [];
            $this->log->script_log("STIG ID " . $this->groups[$this->group_id]['version'] . " is not in the database, adding", E_WARNING);
            $pdi = new pdi(null, '', 'NOW');
            $pdi->set_Short_Title($this->groups[$this->group_id]['title']);
            $pdi->set_Group_Title($this->groups[$this->group_id]['title']);
            $pdi->set_Description($this->groups[$this->group_id]['desc']);
            $pdi_id = $this->db->save_PDI($pdi);
            $stig = new stig($pdi_id, $this->groups[$this->group_id]['version'], $this->groups[$this->group_id]['title']);
            $this->db->add_Stig($stig);
            $this->groups[$this->group_id]['stig'] = $stig;

            if (! empty($this->groups[$this->group_id]['desc'])) {
                $match = array();
                if (preg_match("/\<IAControls\>(.*)\<\/IAControls\>/", $this->groups[$this->group_id]['desc'], $match)) {
                    $ias = explode(", ", $match[1]);
                    if (is_array($ias) && count($ias)) {
                        foreach ($ias as $ia) {
                            $ia_controls[] = new ia_control($pdi_id, substr($ia, 0, 4), substr($ia, - 1));
                        }
                    } else {
                        $ia_controls[] = new ia_control($pdi_id, "ECSC", 1);
                    }
                }
            } else {
                $ia_controls[] = new ia_control($pdi_id, 'ECSC', 1);
            }

            $this->db->save_IA_Control($ia_controls);
        }

        if (empty($this->vms)) {
            $this->vms = new golddisk($this->groups[$this->group_id]['stig']->get_PDI_ID(), $this->vms_id, $this->groups[$this->group_id]['title']);
            $this->db->save_GoldDisk($this->vms);
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:target-facts\cdf:fact tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_target_facts_cdf_fact($attrs)
    {
        $tmp = explode(":", $attrs['name']);
        $this->tag_id = end($tmp);
        if (isset($this->tag[$this->tag_id])) {
            if ($this->tag_id == 'interface_name') {
                $this->int_count ++;
            }
            $this->tag_id .= $this->int_count;
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:target-facts\cdf:fact character data
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_target_facts_cdf_fact_data($data)
    {
        $this->tag[$this->tag_id] = str_replace("\n", "", $data);
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:target-facts end tag and store results
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_target_facts_end()
    {
        // error_log(print_r($this->tag, true));
        $host_name = $this->tag['host_name'];
        if (preg_match("/\./", $host_name)) {
            $host_name = preg_replace("/^([^.]+).*/i", "$1", $host_name);
        }

        if (! ($tgt_id = $this->db->check_Target($this->ste_id, $host_name))) {
            $this->log->script_log("Creating new target with hostname $host_name", E_DEBUG);
            $os = array();
            if (isset($this->tag['os_name']) && isset($this->tag['os_version']) && is_numeric($this->tag['os_version'])) {
                $this->tag['os_name'] .= " {$this->tag['os_version']}";
            }

            if (isset($this->tag['os_name'])) {
                $os_regex = $this->db->get_Regex_Array("os");
                $os = software::identify_Software($os_regex, $this->tag['os_name']);
                $os = $this->db->get_Software($os);
            }

            $this->log->script_log("Identified OS " . print_r($os, true), E_DEBUG);

            if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
                $os = $os[0];
            } else {
                $os = $this->db->get_Software("cpe:/o:generic:generic:-")[0];
            }

            if (! is_a($os, 'software')) {
                $this->log->script_log("Failed to identify the OS", E_ERROR);
            }

            $tgt = new target($host_name);
            $tgt->set_STE_ID($this->ste_id);
            $tgt->set_Notes("New target found by SCC");

            if (is_a($os, "software")) {
                $this->log->script_log("Assigning OS {$os->get_CPE()}", E_DEBUG);

                $tgt->set_OS_ID($os->get_ID());
                $tgt->set_OS_String($os->get_Shortened_SW_String());
            }

            $tgt_id = $this->db->save_Target($tgt);
        }

        $this->tgt = $this->db->get_Target_Details($this->ste_id, $tgt_id)[0];

        $int_keys = preg_grep("/interface_name/", array_keys($this->tag));
        $match = [];
        foreach ($int_keys as $key) {
            $idx = '';
            if (preg_match("/interface_name(\d+)/", $key, $match)) {
                $idx = $match[1];
            }

            if (isset($this->tag["ipv4$idx"])) {
                $ip = explode(",", $this->tag["ipv4$idx"]);

                $ipv4 = null;
                $ipv6 = null;

                if (is_array($ip) && count($ip) == 1) {
                    if (preg_match("/\d+\./", $ip[0])) {
                        $ipv4 = $ip[0];
                    } elseif (preg_match("/[a-f0-9]+/", $ip[0])) {
                        $ipv6 = $ip[0];
                    }
                } elseif (is_array($ip) && count($ip) == 2) {
                    $ipv4 = $ip[0];
                    $ipv6 = $ip[1];
                }

                if ($ipv4) {
                    $int = new interfaces(null, $tgt_id, $this->tag["interface_name$idx"], $ipv4, null, (isset($this->tag['host_name']) ? $this->tag['host_name'] : ""), (isset($this->tag['fqdn']) ? $this->tag['fqdn'] : ""), null);
                    if (isset($this->tag["mac$idx"])) {
                        $int->set_MAC($this->tag["mac$idx"]);
                    }
                    $this->db->save_Interface($int);
                }

                if ($ipv6) {
                    $int = new interfaces(null, $tgt_id, $this->tag["interface_name$idx"], null, $ipv6, (isset($this->tag['host_name']) ? $this->tag['host_name'] : ""), (isset($this->tag['fqdn']) ? $this->tag['fqdn'] : ""), null);
                    if (isset($this->tag["mac$idx"])) {
                        $int->set_MAC($this->tag["mac$idx"]);
                    }
                    $this->db->save_Interface($int);
                }
            }
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:platform tag (stores CPE)
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_platform($attrs)
    {
        if (isset($attrs['idref']) && substr($attrs['idref'], 0, 3) == 'cpe') {
            $cpe = $attrs['idref'];

            $sw = $this->db->get_Software($cpe);

            if (is_array($sw) && count($sw) && is_a($this->tgt, 'target')) {
                $sw = $sw[0];
                if ($sw->is_OS() && $this->tgt->get_OS_ID() != $sw->get_ID()) {
                    $this->log->script_log("Update OS " . $sw->get_CPE());
                    $this->tgt->set_OS_ID($sw->get_ID());
                    $this->tgt->set_OS_String($sw->get_Shortened_SW_String());
                } elseif (! $sw->is_OS() && ! in_array($sw, $this->tgt->software)) {
                    $this->log->script_log("Assigning software " . $sw->get_CPE());
                    $this->tgt->software[] = $sw;
                }
            }

            $this->db->save_Target($this->tgt);
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:rule-result tag
     *
     * @param array $attrs
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_rule_result($attrs)
    {
        $stig = $this->db->get_Stig($attrs['version']);
        $sv_rule = $this->db->get_SV_Rule(null, $attrs['idref']);

        $this->log->script_log("Version: {$attrs['version']}", E_DEBUG);
        $this->log->script_log("STIG data: " . print_r($stig, true), E_DEBUG);

        if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
            $stig = $stig[0];
            $this->group_id = $stig->get_PDI_ID();
        } elseif (is_array($sv_rule) && count($sv_rule) && isset($sv_rule[0]) && is_a($sv_rule[0], 'sv_rule') && ! $this->group_id) {
            $sv_rule = $sv_rule[0];
            $this->group_id = $sv_rule->get_PDI_ID();
        } else {
            $this->log->script_log("Cannot find PDI ID (" . $attrs['version'] . "/" . $attrs['idref'] . ") CREATING", E_WARNING);

            $this->group_id = null;

            return;
            /*
             * $level = 1;
             * if ($attrs['severity'] == 'medium') {
             * $level = 2;
             * }
             * elseif ($attrs['severity'] == 'low') {
             * $level = 3;
             * }
             * $pdi = new pdi(null, $level, new DateTime);
             * $pdi_id = $this->db->save_PDI($pdi);
             *
             * $this->group_id = $pdi_id;
             *
             * if (!empty($attrs['version'])) {
             * $stig = new stig($pdi_id, $attrs['version'], null, null);
             * $this->db->add_Stig($stig);
             * }
             *
             * if (!empty($attrs['idref'])) {
             * $sv_rule = new sv_rule($pdi_id, $attrs['idref']);
             * $this->db->save_SV_Rule($sv_rule);
             * }
             *
             * return;
             */
        }

        if (empty($this->groups[$this->group_id]['sv_rule']) && is_a($sv_rule, "sv_rule")) {
            $this->groups[$this->group_id]['sv_rule'] = $sv_rule;
        }

        if (empty($this->groups[$this->group_id]['stig']) && is_a($stig, "stig")) {
            $this->groups[$this->group_id]['stig'] = $stig;
        }

        if (isset($attrs['severity'])) {
            switch ($attrs['severity']) {
                case 'low':
                    $this->groups[$this->group_id]['cat'] = 3;
                    break;
                case 'high':
                    $this->groups[$this->group_id]['cat'] = 1;
                    break;
            }
        }
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:rule-result\cdf:result character data
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_rule_result_cdf_result_data($data)
    {
        if (preg_match("/pass|true/i", $data)) {
            $this->groups[$this->group_id]['status'] = "Not a Finding";
        } elseif (preg_match("/fail|false/i", $data)) {
            $this->groups[$this->group_id]['status'] = "Open";
        }

        $this->log->script_log("{$this->group_id} {$this->groups[$this->group_id]['status']}", E_DEBUG);
    }

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult\cdf:rule-result\cdf:ident character data
     *
     * @param string $data
     */
    public function cdf_Benchmark_cdf_TestResult_cdf_rule_result_cdf_ident_data($data)
    {}

    /**
     * Function to parse \cdf:Benchmark\cdf:TestResult end tag and store all results
     */
    public function cdf_Benchmark_cdf_TestResult_end()
    {
        $new_findings = [];
        $update_findings = [];
        $existing_findings = $this->db->get_Finding($this->tgt);
        foreach ($this->groups as $pdi_id => $group) {
            if (! empty($group['val_id'])) {
                $note = "(SCC) " . $group['val_id'] . "\nRequired: " . $group['value'] . "\nActual: " . $this->values[$group['val_id']];
            } else {
                $note = "(SCC) ";
            }

            /*
            if (isset($group['stig']) && is_a($group['stig'], 'stig')) {
                $ref = $group['stig'];
            } elseif (! empty($group['vms_id'])) {
                $vms = $this->db->get_GoldDisk($group['vms_id']);
                if (is_array($vms) && count($vms) && isset($vms[0]) && is_a($vms[0], 'golddisk')) {
                    $ref = $vms[0];
                }
            } elseif (isset($group['sv_rule']) && is_a($group['sv_rule'], 'sv_rule')) {
                $ref = $group['sv_rule'];
            } else {
                $this->log->script_log("Error finding reference to search for PDI $pdi_id\n" . print_r($group, true), E_WARNING);
                continue;
            }
            */

            if (is_array($existing_findings) && count($existing_findings) && isset($existing_findings[$pdi_id])) {
                /** @var finding $finding */
                $finding = $existing_findings[$pdi_id];

                $finding->set_Finding_Status_By_String($finding->get_Deconflicted_Status($group['status']));
                if(preg_match("/" . preg_quote($note, "/") . "/", $finding->get_Notes())) {
                    $finding->set_Notes($note);
                } else {
                    $finding->prepend_Notes($note);
                }

                $update_findings[$pdi_id] = $finding;
            } else {
                $new_findings[$pdi_id] = new finding($this->tgt->get_ID(), $pdi_id, $this->scan->get_ID(), $group['status'], $note, finding::NC, null, 1);
            }
        }

        $this->db->add_Findings_By_Target($update_findings, $new_findings);

        $hl = new host_list();
        $hl->setTargetId($this->tgt->get_ID());
        $hl->setTargetName($this->tgt->get_Name());
        $hl->setFindingCount(count($new_findings) + count($update_findings));

        $this->db->update_Target_Counts($this->tgt->get_ID());

        $this->scan->add_Target_to_Host_List($hl);
        $this->db->update_Scan_Host_List($this->scan);
    }
}

$xml = new scc_parser($conf['ste'], $cmd['f']);
$xml->debug = (isset($cmd['debug']) ? true : false);
$xml->parse();

if (! $xml->debug) {
    rename($cmd['f'], TMP . "/scc/" . $base_name);
}
$db->update_Running_Scan($base_name, [
    "name" => "perc_comp",
    "value" => 100,
    "complete" => 1
]);

function usage()
{
    print <<<EOO
Purpose: To import an XCCDF result file from Security Compliance Checker 3.1+

Usage: php parse_scc_xccdf.php -s={ST&E ID} -f={XCCDF result file} [--debug] [--help]

 -s={ST&E ID}       The ST&E ID this result file is being imported for
 -f={XCCDF file}    The result file to import (will not import oval, dictionary, or other files)

 --debug            Debugging output
 --help             This screen

EOO;
}
