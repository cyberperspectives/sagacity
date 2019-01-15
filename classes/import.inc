<?php

/**
 * File: import.inc
 * Author: Ryan Prather
 * Purpose: Class to allow the parsing and traversing of the tmp directory to find result files to import
 * Created: Sep 27, 2013
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
 *  - Sep 27, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright, updated purpose, and updated to make platform independent
 *  - Oct 24, 2016 - Cleaned up script call string and converted to use PHP_OS constant instead of php_uname() function
 *  - Nov 7, 2016 - Made several updates to the scan_Result_Files function
 *  - Dec 7, 2016 - Fixed bug in scan_Result_Files where Windows threading was not being run and changed PHP constant to PHP_BIN
 *  - Jan 30, 2017 - Added parse_config.ini file when parsing and execution check for Linux and Windows
 *  - Feb 15, 2017 - Fix bug with PHP_BIN not being declared for some reason (need to troubleshoot further)
 *  - Feb 21, 2017 - Fixed path issues with scripts not running
 *  - Jun 27, 2017 - Removed include for PHPExcel.php library
 *  - Oct 23, 2017 - Fixes for pdi class
 *  - May 24, 2018 - Added throwing error if not able to create /exec/parse_config.ini
 */
include_once 'config.inc';
include_once 'database.inc';
include_once 'echecklist.inc';
include_once 'helper.inc';
include_once 'vendor/autoload.php';

/**
 * Class to control the importing of files
 *
 * @author Ryan Prather
 */
class import
{

    /**
     * The current include_once path
     *
     * @var string
     */
    protected $current_path = '';

    /**
     * String array of regular expressions.
     * Files matching these expressions will be skipped
     *
     * @var string
     */
    protected $SKIP = array(
        '/HBSS/i',
        '/SharePoint/i',
        '/ISSE/i',
        '/_[Mm]ac/i',
        '/Guard/i',
        '/SME_PED/i',
        '/_zOS_/i',
        '/BlackBerry/i',
        '/C2\-Fix/i',
        '/Enclave_Zone/i',
        '/General_Mobile/i',
        '/Remote_/i',
        '/_Tandem/i',
        '/xenapp/i',
        '/internet/i',
        '/android/i',
        '/JVAP/i',
        '/apple/i',
        '/OpenVMS/i',
        '/VVoIP/i',
        '/Wireless/i',
        '/REL-LAN/i',
        '/dictionary/i',
        '/IBM_/i',
        '/Smartphone/i',
        '/Exchange/i',
        '/Juniper/i',
        '/Mobility/i',
        '/ESXi/i',
        '/FW_SRG/i',
        '/PlayBook_OS/i',
        '/vCenter_Server/i'
    );

    /**
     * Class constructor
     */
    public function __construct()
    {
        set_time_limit(0);
    }

    /**
     * Class destructor to reset the include_once path and time limits
     */
    public function __destruct()
    {
        set_time_limit(30);
    }

    /**
     * Function to scan the tmp directory for result files and call the appropriate parsers
     */
    public function scan_Result_Files($redirect = true)
    {
        chdir(DOC_ROOT . "/exec");

        $ignore = filter_input(INPUT_POST, 'ignore', FILTER_VALIDATE_BOOLEAN) ? "true" : "false";
        $doc_root = realpath(DOC_ROOT);
        $ste = filter_input(INPUT_COOKIE, 'ste', FILTER_VALIDATE_INT);
        if (! $ste) {
            $ste = filter_input(INPUT_POST, 'ste', FILTER_VALIDATE_INT);
        }
        $location = filter_input(INPUT_POST, 'location', FILTER_SANITIZE_STRING);

        $conf = <<<EOF
[system_params]
ste = $ste
location = $location
doc_root = $doc_root
ignore = $ignore

EOF;

        if (! file_put_contents(DOC_ROOT . "/exec/parse_config.ini", $conf)) {
            throw new Exception("Error creating the parse_config.ini");
        }

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) . " -c " . realpath(PHP_CONF) . " -f " . realpath(DOC_ROOT . "/exec/background_results.php");

        if (LOG_LEVEL == E_DEBUG) {
            Sagacity_Error::err_handler("Script to execute: $script", E_DEBUG);
        }

        $process = new Cocur\BackgroundProcess\BackgroundProcess("cd " . realpath(DOC_ROOT . "/exec") . " && " . $script);
        $process->run();

        if ($redirect) {
            header("/results/");
        }
    }

    /**
     * Function to scan '/xampp/www/tmp' directory for catalog files
     */
    public function scan_Catalog_Files()
    {
        chdir(DOC_ROOT . "/tmp");
        $files = glob("*");

        foreach ($files as $file) {
            if (substr($file, - 3) == 'zip') {
                // $this->import_STIG_ZIP("../tmp/$file");
            } elseif (preg_match('/pdi\-|\_catalog/i', $file)) {
                // $this->import_PDI_CSV("../tmp/$file");
            } elseif (preg_match('/\-xccdf\.xml$/i', $file)) {
                // $this->import_STIG("../tmp/$file");
            }
        }
    }

    /**
     * Function to scan host data files and import findings
     */
    public function import_Host_Data_Collection()
    {
        $db = new db();

        $doc_root = realpath(DOC_ROOT);
        $overwrite = (isset($_REQUEST['overwrite']) && $_REQUEST['overwrite'] ? "true" : "false");

        $conf = <<<EOF
[system_params]
ste = {$_REQUEST['ste']}
location = "{$_REQUEST['location']}"
doc_root = $doc_root
target = {$_REQUEST['tgt']}
overwrite = $overwrite

EOF;

        file_put_contents(DOC_ROOT . "/exec/parse_config.ini", $conf);

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) . " -c " . realpath(PHP_CONF) . " -f " . realpath(DOC_ROOT . "/exec/parse_host_data_collection.php");

        if (substr(strtolower(PHP_OS), 0, 3) == 'win') {
            $shell = new COM("WScript.Shell");
            $shell->CurrentDirectory = DOC_ROOT;
            $shell->run($script, 0, false);
        } elseif (substr(strtolower(PHP_OS), 0, 3) == 'lin') {
            exec("$script > /dev/null &");
        } else {
            Sagacity_Error::err_handler("Unknown OS: " . PHP_OS);
        }

        header("Location: /ste/");
    }

    /**
     * function to import PDI CSV file to database
     */
    public function import_PDI_CSV()
    {
        $db = new db();

        $handle = fopen(DOC_ROOT . "/tmp/All-PDI-Catalog.csv", "r");
        $data = fgetcsv($handle);
        $data = fgetcsv($handle);

        while ($data = fgetcsv($handle)) {
            $catalog = array(
                'stig_id' => (isset($data[0]) ? $data[0] : ""),
                'vms_id' => (isset($data[1]) ? $data[1] : ""),
                'cat_lvl' => (isset($data[2]) ? $data[2] : "II"),
                'ia_controls' => (isset($data[3]) ? $data[3] : ""),
                'short_title' => (isset($data[4]) ? $data[4] : ""),
                'description' => (isset($data[5]) ? $data[5] : ""),
                'notes' => (isset($data[6]) ? $data[6] : ""),
                'retina_id' => (isset($data[7]) ? $data[7] : ""),
                'vul_id' => (isset($data[8]) ? $data[8] : ""),
                'check_contents' => (isset($data[9]) ? $data[9] : ""),
                'sv_rule_id' => (isset($data[10]) ? $data[10] : ""),
                'nessus_id' => (isset($data[11]) ? $data[11] : "")
            );

            if ($catalog['stig_id'] != 'No Reference') {
                $ref = $db->get_STIG($catalog['stig_id']);
            }

            if (is_null($ref) && $catalog['vms_id'] != 'No Reference') {
                $ref = $db->get_GoldDisk($catalog['vms_id']);
            }

            if (is_array($ref) && count($ref) && isset($ref[0])) {
                $ref = $ref[0];
            }

            if (! is_null($ref)) {
                $pdi = new pdi($ref->get_PDI_ID(), $catalog['cat_lvl'], "NOW");
                $pdi->set_Short_Title($catalog['short_title']);
                $pdi->set_Group_Title($catalog['short_title']);
                $pdi->set_Description($catalog['description']);

                if ($catalog['ia_controls']) {
                    $ia_controls = array();
                    foreach (explode(" ", $catalog['ia_controls']) as $ia) {
                        $ia_controls[] = new ia_control($ref->get_PDI_ID(), substr($ia, 0, - 2), substr($ia, - 1));
                    }

                    if (! $db->save_IA_Control($ia_controls)) {
                        print "error updating ia controls on id: " . $ref->get_ID() . "<br />";
                    }
                }

                // Check for retina data
                if ($catalog['retina_id']) {
                    $retina = new retina($ref->get_PDI_ID(), $catalog['retina_id']);

                    if (! $db->save_Retina($retina)) {
                        print "error updating retina id: " . $catalog['retina_id'] . "<br />";
                    }
                }

                // Vul_ID
                if ($catalog['vul_id']) {}

                if ($catalog['sv_rule_id']) {
                    $sv_rule = array();
                    foreach (explode(" ", $catalog['sv_rule_id']) as $rule) {
                        $sv_rule[] = new sv_rule($ref->get_PDI_ID(), $rule);
                    }

                    if (! $db->save_SV_Rule($sv_rule)) {
                        print "error updating sv rule on pdi: " . $ref->get_ID() . "<br />";
                    }
                }

                if ($catalog['nessus_id']) {
                    $nessus = new nessus($ref->get_PDI_ID(), $catalog['nessus_id']);

                    if (! $db->save_Nessus($nessus)) {
                        print "error updating nessus id: " . $catalog['nessus_id'] . "<br />";
                    }
                }
            } else {
                $pdi = new pdi(0, $catalog['cat_lvl'], "NOW");
                $pdi->set_Short_Title($catalog['short_title']);
                $pdi->set_Group_Title($catalog['short_title']);
                $pdi->set_Description($catalog['description']);

                $pdi_id = $db->save_PDI($pdi);

                if ($catalog['stig_id'] != 'No Reference') {
                    $stig = new stig($pdi_id, $catalog['stig_id'], $catalog['description']);
                    $ref = $stig;
                    $db->add_Stig($stig);
                }

                if ($catalog['vms_id'] != 'No Reference') {
                    $golddisk = new golddisk($pdi_id, $catalog['vms_id'], $catalog['short_title']);

                    if ($ref == null) {
                        $ref = $golddisk;
                    }

                    $db->save_GoldDisk($golddisk);
                }

                if ($catalog['ia_controls']) {
                    $ia_controls = array();
                    foreach (explode(" ", $catalog['ia_controls']) as $ia) {
                        $ia_controls[] = new ia_control($pdi_id, substr($ia, 0, - 2), substr($ia, - 1));
                    }

                    if (! $db->save_IA_Control($ia_controls)) {
                        print "error updating ia controls on pdi_id: " . $ref->get_ID() . "<br />";
                    }
                }

                // Check for retina data
                if ($catalog['retina_id']) {
                    $retina = new retina($pdi_id, $catalog['retina_id']);

                    if (! $db->save_Retina($retina)) {
                        print "error updating retina id: " . $catalog['retina_id'] . "<br />";
                    }
                }

                // Vul_ID
                if ($catalog['vul_id']) {}

                // sv_rule
                if ($catalog['sv_rule_id']) {
                    $sv_rule = array();
                    foreach (explode(" ", $catalog['sv_rule_id']) as $rule) {
                        $sv_rule[] = new sv_rule($pdi_id, $rule);
                    }

                    if (! $db->save_SV_Rule($sv_rule)) {
                        print "error updating sv rule on pdi: " . $ref->get_ID() . "<br />";
                    }
                }

                if ($catalog['nessus_id']) {
                    $nessus = new nessus($pdi_id, $catalog['nessus_id']);

                    if (! $db->save_Nessus($nessus)) {
                        print "error updating nessus id: " . $catalog['nessus_id'] . "<br />";
                    }
                }
            }
        }
        fclose($handle);
    }

    /**
     * function for SRR script
     * runs script net-SRR.pl
     * exports a csv format file
     */
    public function net_SRR()
    {}

    /**
     * function for unix SRR conversion to csv
     * runs script unix-xml-to-echecklist.pl
     * runs script unix-srr-to-csv.pl
     */
    public function unix_srr_to_csv()
    {}

    /**
     * Function to import DISA STIG content to database
     *
     * @param array $request
     */
    public function import_STIG_XML($request = array())
    {
        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) . " " . realpath(DOC_ROOT . "/exec/background_stigs.php") . " " . (isset($request['delete']) ? ' --delete' : '') . (isset($request['override']) ? " --ia" : "");

        $shell = new COM("WScript.Shell");
        $shell->CurrentDirectory = DOC_ROOT . "/exec";
        $shell->run($script, 0, false);

        header("location: " . $_SERVER['HTTP_REFERER']);
    }

    /**
     * Function to convert a retina CSV to an eChecklist and store on database
     */
    public function retina_csv_echecklist()
    {
        $files = glob('*.csv');
        $db = new db();

        $source = $db->get_Sources('Retina');
        $ste = $db->get_STE($_REQUEST['ste'])[0];

        foreach ($files as $file) {
            $scan = new scan(null, $source, $ste, '1', $file, 'CURRENT_TIMESTAMP');
            $db->save_Scan($scan);

            exec(PERL . "/perl " . DOC_ROOT . "/exec/retina-csv-to-echecklist.pl " . DOC_ROOT . "/tmp/$file --db", $output, $result);
        }
    }

    /**
     * function to import golddisk info into scans table
     * runs script golddisk-xml-to-echecklist.pl
     */
    public function golddisk_xml_echecklist()
    {
        $files = glob('*.xml');
        $db = new db();

        $source = $db->get_Sources('Golddisk');
        $ste = $db->get_STE($_REQUEST['ste'])[0];

        foreach ($files as $file) {
            $scan = new scan(null, $source, $ste, '1', $file, 'CURRENT_TIMESTAMP');
            $db->save_Scan($scan);

            exec(PERL . "/perl " . DOC_ROOT . "/exec/golddisk-xml-to-echecklist.pl " . DOC_ROOT . "/tmp/$file --db", $output, $result);
        }
    }

    /**
     */
    public function import_IAVM_CVE()
    {
        $filename = '../tmp/iavm-to-cve(u).xml';
        $xml = simplexml_load_file($filename);
        $db = new db();

        foreach ($xml->IAVM as $iavm) {
            $vms_id = preg_replace('/V[0]+/', 'V-', (string) $iavm->S['VMSKey']);
            $stig_id = (string) $iavm->S['IAVM'];
            $title = (string) $iavm->S['Title'];
            $release_date = DateTime::createFromFormat('d M Y', $iavm->S['ReleaseDate']);
            $revision_date = DateTime::createFromFormat('d M Y', $iavm->Revision['Date']);

            $cves_tags = $iavm->CVEs;
            $cves = array();

            $pdi = $db->get_Stig($stig_id);
            if (is_array($pdi) && count($pdi) && isset($pdi[0]) && is_a($pdi[0], 'stig')) {
                $pdi = $pdi[0];
            }

            if (is_null($pdi)) {
                $pdi = $db->get_GoldDisk($vms_id);
                if (is_array($pdi) && count($pdi) && isset($pdi[0]) && is_a($pdi[0], 'golddisk')) {
                    $pdi = $pdi[0];
                }
            }

            if (is_null($pdi)) {
                $cat_lvl = substr_count((string) $iavm->S['Severity'], 'I');
                $pdi = new pdi(null, $cat_lvl, (string) $iavm->S['ReleaseDate']);
                $pdi->set_Short_Title($title);
                $pdi->set_Group_Title($title);
                $pdi->set_Description($title);
                $pdi_id = $db->save_PDI($pdi);

                $stig = new stig($pdi_id, $stig_id, $title);
                $db->add_Stig($stig);

                $golddisk = new golddisk($pdi_id, $vms_id, $title);
                $db->save_GoldDisk($golddisk);
            } else {
                $pdi_id = $pdi->get_PDI_ID();
            }

            foreach ($cves_tags->CVENumber as $cve) {
                $cve_id = (string) $cve;

                $cves[] = new cve(null, $cve_id, $release_date, $title);
            }

            $db->add_CVE($cves);

            $ref_tags = $iavm->References;
            $refs = array();

            foreach ($ref_tags->Reference as $ref) {
                $ref_type = '';
                $adv_id = '';
                $url = (string) $ref['URL'];
                $name = (string) $ref['RefName'];
                $match = array();

                $refs[] = new advisory($pdi_id, $adv_id, $name, $ref_type, $url);
            }
        }

        $ref = $row[8];
        $url = $row[9];

        if (strpos($ref, 'Microsoft') !== false) {
            $x ++;
            $type = 'Microsoft';
            $ret = preg_match('/(MS\d{2}\-\d{3}|KB\d{6,7}|\d{6,7})/', $ref, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Adobe') !== false) {
            $x ++;
            $type = 'Adobe';
            $ret = preg_match('/(APSA\d{2}\-\d{2}|APSB\d{2}\-\d{2})/', $ref, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Apache') !== false) {
            $x ++;
            $type = 'Apache';
            $ret = preg_match('/(CVE\-\d{4}\-\d{4}|S\d\-\d{3})/', $ref, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'CERT') !== false) {
            $x ++;
            $type = 'US-CERT';
            $match = array();

            if (strpos($url, 'techalerts') !== false) {
                $ret = preg_match('/(TA\d{2}\-\d{3}\s).html/', $url, $match);
            } elseif (strpos($url, 'vuls') !== false) {
                $ret = preg_match('/([^\/]+)$/', $url, $match);
            }

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Cisco') !== false) {
            $x ++;
            $type = 'Cisco';
            $ret = preg_match('/([^\/]+)(\.s?html)$/', $url, $match);

            if (count($match) > 0) {
                $id = $match[1];
            } else {
                $ret = preg_match('/([^\/]+)$/', $url, $match);
                if (count($match)) {
                    $id = $match[1];
                }
            }
        } elseif (strpos($ref, 'Citrix') !== false) {
            $x ++;
            $type = 'Citrix';
            $ret = preg_match('/([^\/]+)$/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Debian') !== false) {
            $x ++;
            $type = 'Debian';
            $ret = preg_match('/([^\/]+)$/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'HP') !== false) {
            $x ++;
            $type = 'HP';
            $ret = preg_match('/(HPSB\S+\ SSRT\S+)[\ ?\)?]/', $ref, $match);

            if (count($match)) {
                $id = $match[1];
            } else {
                $ret = preg_match('/(HPSB\S+)[\ ?\)?]/', $ref, $match);
                if (count($match)) {
                    $id = $match[1];
                }
            }
        } elseif (strpos($ref, 'IBM') !== false) {
            $x ++;
            $type = 'IBM';
            $ret = preg_match('/(\d{5,8})/', $ref, $match);

            if (count($match)) {
                $id = $match[1];
            } else {
                $ret = preg_match('/([^\=|\/]+)$/', $url, $match);
                if (count($match)) {
                    $id = $match[1];
                }
            }
        } elseif (strpos($ref, 'Juniper') !== false) {
            $x ++;
            $type = 'Juniper';
            $ret = preg_match('/(PSN\-\d{4}\-\d{2}\-\d{3}|JSA\d{5})/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Oracle') !== false) {
            $x ++;
            $type = 'Oracle';
            $url = basename($url);
            $ret = preg_match('/([\S]+)\.html/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'McAfee') !== false) {
            $x ++;
            $type = 'McAfee';
            $query = parse_query($url);

            if (count($match)) {
                $id = isset($query['id']) ? $query['id'] : '';
            }
        } elseif (strpos($ref, 'Red Hat') !== false) {
            $x ++;
            $type = 'Red Hat';
            $ret = preg_match('/([^\/]+)\.html/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Secunia') !== false) {
            $x ++;
            $type = 'Secunia';
            $ret = preg_match('/([^\/]+)\/([^\/]+)\/?$/', $url, $match);

            if (count($match)) {
                if ($match[2] == 'advisory') {
                    $id = $match[1];
                } elseif (is_numeric($match[1]) && count($match[2]) == 1) {
                    $id = $match[1];
                } else {
                    $id = $match[2];
                }
            }
        } elseif (strpos($url, 'securitytracker') !== false) {
            $x ++;
            $type = 'Security Tracker';
            $ret = preg_match('/([^\/]+)\.html$/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'SecurityFocus') !== false) {
            $x ++;
            $type = 'SecurityFocus';
            $ret = preg_match('/([^\/]+)\/?$/', $url, $match);

            if (count($match)) {
                if ($match[1] != 'info') {
                    $id = $match[1];
                } else {
                    $ret = preg_match('/([^\/]+)\/info/', $url, $match);
                    $id = $match[1];
                }
            }
        } elseif (strpos($ref, 'Sun') !== false) {
            $x ++;
            $type = 'Sun';
            $query = parse_query($url);

            $id = isset($query['assetkey']) ? $query['assetkey'] : '';

            if (! $id) {
                $ret = preg_match('/([^\/]+)$/', parse_url($url, PHP_URL_PATH), $match);
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Symantec') !== false) {
            $x ++;
            $type = 'Symantec';
            $ret = preg_match('/(\d{5}|SYM\d{2}\-\d{3})/', $ref, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($url, 'ZDI') !== false) {
            $x ++;
            $type = 'ZDI';
            $ret = preg_match('/([^\/]+)(\.html|\/)$/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        } elseif (strpos($ref, 'Wireshark') !== false) {
            $x ++;
            $type = 'Wireshark';
            $ret = preg_match('/([^\/]+)\.html$/', $url, $match);

            if (count($match)) {
                $id = $match[1];
            }
        }
    }

    /**
     *
     * @param string $in
     * @return multitype:Ambigous <>
     */
    public function parse_query($in)
    {
        /**
         * Use this function to parse out the query array element from
         * the output of parse_url().
         */
        $query_string = substr($in, strpos($in, '?') + 1);
        $query_arr = explode('&', $query_string);
        $arr = array();

        foreach ($query_arr as $val) {
            $x = explode('=', $val);
            $arr[$x[0]] = isset($x[1]) ? $x[1] : '';
        }
        unset($val, $x, $var);
        return $arr;
    }

    /**
     * Function for fixing a DISA OVAL file
     */
    public function fix_Oval()
    {
        chdir("../tmp");
        $files = glob("*-oval.xml");
        $ret = '';
        $db = new db();

        foreach ($files as $file) {
            $xml = new DOMDocument();
            if (! $xml->load($file)) {
                error_log("error reading xml file");
            }
            $xml->formatOutput = true;
            $xml->preserveWhiteSpace = true;
            $const_arr = null;

            $variables = $xml->getElementsByTagName("variables")->item(0);
            $first_node = $variables->firstChild;
            while ($node = $xml->getElementsByTagName("external_variable")->item(0)) {
                $id = $node->getAttribute("id");
                $id = explode(':', $id)[3];

                $comment = $node->getAttribute("comment");
                $ver = $node->getAttribute("version");
                $datatype = $node->getAttribute("datatype");

                $tmp = $db->get_Oval_Const($id);
                $const_arr[$tmp['const_id']]['values'] = $tmp['values'];
                $const_arr[$tmp['const_id']]['ver'] = $ver;
                $const_arr[$tmp['const_id']]['datatype'] = $datatype;
                $const_arr[$tmp['const_id']]['comment'] = $comment;

                $var_com = $xml->createElement('variable_component');
                $var_com->setAttribute('var_ref', "oval:smc.gpea.windows:var:" . $tmp['const_id']);

                $loc_var = $xml->createElement('local_variable');
                $loc_var->setAttribute('id', "oval:mil.disa.fso.windows:var:" . $id);
                $loc_var->setAttribute('version', $ver);
                $loc_var->setAttribute('datatype', $datatype);
                $loc_var->setAttribute('comment', $comment);
                $loc_var->appendChild($var_com);

                $variables->replaceChild($loc_var, $node);
            }

            foreach ($const_arr as $key => $value) {
                $const_var = $xml->createElement('constant_variable');
                $const_var->setAttribute('id', 'oval:smc.gpea.windows:var:' . $key);
                $const_var->setAttribute('version', $const_arr[$key]['ver']);
                $const_var->setAttribute('datatype', $const_arr[$key]['datatype']);
                $const_var->setAttribute('comment', $const_arr[$key]['comment']);

                foreach ($value['values'] as $val) {
                    $txt = $xml->createTextNode($val);
                    $val_var = $xml->createElement("value");
                    $val_var->appendChild($txt);

                    $const_var->appendChild($val_var);
                }

                $variables->appendChild($const_var);
            }

            rename($file, "oval\\$file");
            return $xml->saveXML();
        }
    }

    private function getElementById($doc, $id)
    {
        $xpath = new DOMXPath($doc);
        return $xpath->query("//*[@id='$id']")->item(0);
    }
}
