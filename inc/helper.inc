<?php
/**
 * File: helper.inc
 * Author: Ryan Prather
 * Purpose: The purpose of this file is to hold any helper functions that are used in various locations in the application
 * Created: 6 Jan 2014
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
 *  - 6 Jan 14 - File created
 *  - Sep 1, 2016 - Copyright Update and
 * 					changed file types to string instead of index
 *  - Oct 24, 2016 - Added check in download_file function to ensure can open the local file
 *  - Nov 7, 2016 - Added check for existence of file_types class before creating
 *  - Dec 7, 2016 - Changed PHP constant to PHP_BIN
 *  - Dec 12, 2016 - Added parsing for company variables in config.xml
 *  - Dec 13, 2016 - Changed error in load_Config() to die if it can't find the config.xml file
 *  - Jan 30, 2017 - Formatting
 *  - Feb 15, 2017 - Added BZip, ping, between, and url_exists functions
 *                   Migrated file_types constants to defined constants
 *  - Feb 21, 2017 - Added documentation, fixed issue with remote_filesize not correctly retrieving the file size of a remote file on Windows,
 *                   Started adding download speed checker, but need to troubleshoot
 *  - Mar 3, 2017 - Deleted what_software method (all code is using software::identify_Software method instead)
 *  - Mar 13, 2017 - Cleaned up download_file and url_exists functions
 *  - Mar 22, 2017 - Documentation for constants, added JSON constant for header output,
 *                   Added check for 5-digit extensions (.debug) in check_path,
 *  - Apr 5, 2017 - Added $chdir parameter to check_path function to change directory if set true
 *  - May 13, 2017 - Added ECHECKLIST_OUTPUT_FORMAT constant
 *  - May 19, 2017 - Added NOTIFICATIONS constant
 *  - Oct 2, 2017 - Fixed error with file downloads showing as moved and return largest content-size from http header
 *  - Oct 27, 2017 - Added UNSUPPORTED_INI constant and file detection for desktop.ini files
 *  - Dec 27, 2017 - Expanded download_file method to allow for download progress meta key
 *  - Jun 2, 2018 - Added $salt parameter to my_encrypt method to support changing passwords
 */
include_once 'error.inc';
include_once 'validation.inc';
include_once 'vendor/autoload.php';

use Monolog\Logger;

/**
 * Function to get element or value from XML document using XPath
 *
 * @param DOMDocument $xml
 *        Document
 * @param string $path
 *        XPath string
 * @param string $starting [optional]
 *        Starting node
 * @param boolean $keep [optional]
 *        Return the DOMElement
 *
 * @return mixed
 *    Will a DOMElement if $keep is true, a string if a single element, or an array:string if there are multiple elements
 */
function getValue($xml, $path, $starting = null, $keep = false)
{
    $xpath = new DOMXPath($xml);
    $ns    = $xml->lookupNamespaceUri($xml->namespaceURI);

    $xpath->registerNamespace('x', $ns);
    if (is_null($starting)) {
        $buf = $xpath->query($path);
    }
    else {
        $buf = $xpath->query($path, $starting);
    }
    $ret = null;

    if ($keep) {
        return $buf;
    }

    if ($buf->length == 1) {
        if (get_class($buf->item(0)) == 'DOMAttr') {
            $ret = $buf->item(0)->value;
        }
        elseif (get_class($buf->item(0)) == 'DOMElement' && $buf->item(0)->childNodes->length == 1) {
            $ret = $buf->item(0)->nodeValue;
        }
        elseif (get_class($buf->item(0)) == 'DOMElement' && $buf->item(0)->childNodes->length > 1) {
            foreach ($buf->item(0)->childNodes as $node) {
                if ($node->nodeName != '#text') {
                    $ret[$node->nodeName][] = $node->nodeValue;
                }
            }
        }
    }
    elseif ($buf->length > 1) {
        foreach ($buf as $node) {
            if ($node->childNodes->length == 1) {
                $ret[] = $node->nodeValue;
            }
            elseif ($node->childNodes->length > 1) {
                foreach ($node->childNodes as $childNode) {
                    if ($childNode->nodeName != '#text') {
                        $ret[$childNode->nodeName][] = $childNode->nodeValue;
                    }
                }
            }
        }
    }

    return $ret;
}

/**
 * Function to determine a file type
 *
 * @param string $filename
 *    Path to file being evaulated
 *
 * @return array
 *    <p><i>type</i> - file_types class enum</p>
 *    <p><i>msg</i> - string notice</p>
 *    <p><i>base_name</i> - string file name alone</p>
 */
function FileDetection($filename)
{
    $name['base_name'] = basename($filename);
    // print "\tCheck if exists".PHP_EOL;
    if (!file_exists($filename)) {
        $name['type'] = "ERROR";
        $name['msg']  = "File not found";
        return $name;
    }
    // print "\tCheck if dir".PHP_EOL;
    if (is_dir($filename)) {
        $name['type'] = DIRECTORY;
        return $name;
    }
    // print "\tStarting".PHP_EOL;
    $name['type'] = UNSUPPORTED; // if we can't find it - it stays unsupported
    if (preg_match("/desktop\.ini/", $filename)) {
        $name['type'] = UNSUPPORTED_INI;
        $name['msg']  = 'Unsupported INI';
        return $name;
    }
    // check file extension
    if (preg_match('/\.xml$/i', $name['base_name'])) {
        // STIG XCCDF or SCC Results or XML Nmap
        if (preg_match('/SCC.*XCCDF\-Results.*\.xml/i', $name['base_name'])) {
            $name['type'] = SCC_XCCDF;
        }
        elseif (preg_match('/SCC.*OVAL\-Results.*\.xml/i', $name['base_name'])) {
            $name['type'] = SCC_OVAL;
        }
        elseif (preg_match('/STIG\-(oval|cpe\-dictionary|cpe\-oval)/i', $name['base_name'])) { // DISA STIG Checklist
            $name['type'] = DISA_STIG_OVAL;
        }
        elseif (preg_match('/\$/', $name['base_name'])) { // Invalid DISA STIG checklist
            $name['type'] = UNSUPPORTED_XML;
        }
        elseif (preg_match('/xccdf.*xml/i', $name['base_name'])) { // DISA STIG Checklist
            $name['type'] = DISA_STIG_XML;
        }
        elseif (preg_match('/VMS6X\.xml|Session\.xml/i', $name['base_name'])) { // Gold Disk
            $name['type'] = GOLDDISK;
        }
        elseif (preg_match('/MBSA/i', $name['base_name'])) {
            $name['type'] = MBSA_XML;
        }
        elseif (preg_match("/nmap/i", $name['base_name'])) {
            $name['type'] = NMAP_XML;
        }
        else {
            // could be XML Nmap, or unknown
            $name['type'] = UNSUPPORTED_XML;
            $f            = fopen($filename, 'r');
            for ($x = 0; $x < 5; $x++) {
                $line = fgets($f);
                if (preg_match('/nmap\.xsl|nmaprun/i', $line)) {
                    $name['type'] = NMAP_XML;
                    break;
                }
                elseif (preg_match("/IMPORT_FILE/i", $line)) {
                    $name['type'] = MSSQL_XML;
                    break;
                }
            }
            fclose($f);
        }
    }
    elseif (preg_match('/\.nessus$/i', $name['base_name'])) { // usually starts with nessus_report
        $name['type'] = NESSUS;
    }
    elseif (preg_match('/\.messages$/i', $name['base_name'])) {
        $name['type'] = NESSUS_MESSAGES;
    }
    elseif (preg_match('/\.txt$/i', $name['base_name'])) {
        if (preg_match('/All\-Settings|Non\-Compliance/i', $name['base_name'])) {
            $name['type'] = UNSUPPORTED_SCC_TEXT;
        }
        elseif (preg_match('/SCC.*Error_Log/i', $name['base_name'])) {
            $name['type'] = UNSUPPORTED_SCC_ERROR;
        }
        elseif (preg_match('/MBSA/i', $name['base_name'])) {
            $name['type'] = MBSA_TEXT;
        }
        elseif (preg_match("/nmap/i", $name['base_name'])) {
            $name['type'] = NMAP_TEXT;
        }
        else {
            // see if it's an nmap file named .txt
            $f    = fopen($filename, 'r');
            $line = fgets($f);
            fclose($f);
            if (preg_match('/Nmap/i', $line)) {
                if (preg_match('/\-oN|Starting/i', $line)) {
                    $name['type'] = NMAP_TEXT;
                }
                elseif (preg_match('/\-oG/i', $line)) {
                    $name['type'] = NMAP_GREPABLE;
                }
            }
            elseif (preg_match('/Script started|telnet|User access|sh conf|Using/i', $line)) {
                $name['type'] = NMAP_NETWORK_DEVICE;
            }
            else {
                $name['type'] = UNSUPPORTED_TEXT;
                error_log($name['base_name'] . " is unsupported");
            }
        }
    }
    elseif (preg_match('/All\-PDI\-Catalog\.csv$/i', $name['base_name'])) {
        $name['type'] = PDI_CATALOG;
    }
    elseif (preg_match('/\.csv$/i', $name['base_name'])) {
        // E-Checklist or Retina
        $f    = fopen($filename, 'r');
        $line = fgets($f);
        fclose($f);
        if (preg_match('/Checklist:|Unclassified|Secret|STIG[_| ]ID/i', $line)) {
            $name['type'] = ECHECKLIST_CSV;
        }
        elseif (preg_match('/^\"NetBIOSName|^\"JobName/', $line)) {
            $name['type'] = UNSUPPORTED_RETINA_CSV;
        }
        else {
            $name['type'] = UNSUPPORTED_CSV;
        }
    }
    elseif (preg_match('/\.xlsx$|\.xls$/i', $name['base_name'])) {
        // Could be procedural or technical E-Checklist
        if (preg_match('/e\-?checklist/i', $name['base_name'])) {
            $name['type'] = TECH_ECHECKLIST_EXCEL;
        }
        elseif (preg_match('/validation|ia[\-]*controls/i', $name['base_name'])) {
            $name['type'] = PROC_ECHECKLIST_EXCEL;
        }
        else {
            $name['type'] = UNSUPPORTED_EXCEL;
        }
    }
    elseif (preg_match('/benchmark.*\.zip$/i', $name['base_name'])) {
        $name['type'] = DISA_STIG_BENCHMARK_ZIP;
    }
    elseif (preg_match('/(STIG_Library|IAVM|stig|srg).*\.zip$/i', $name['base_name'])) {
        $name['type'] = DISA_STIG_LIBRARY_ZIP;
    }
    elseif (preg_match('/all\-2\.0\.tar\.gz$/i', $name['base_name'])) {
        $name['type'] = NESSUS_PLUGIN_GZIP;
    }
    elseif (preg_match('/\.nasl$/i', $name['base_name'])) {
        $name['type'] = NESSUS_PLUGIN_NASL;
    }
    elseif (preg_match('/\.ckl$/i', $name['base_name'])) {
        $name['type'] = STIG_VIEWER_CKL;
    }
    elseif (preg_match('/\.nmap$/i', $name['base_name'])) {
        $name['type'] = NMAP_TEXT;
    }
    elseif (preg_match('/\.nbe$/i', $name['base_name'])) {
        $name['type'] = UNSUPPORTED_NESSUS_NBE;
    }
    elseif (preg_match('/\.Result$|\.log$|\.Examples$/i', $name['base_name'])) {
        $name['type'] = UNSUPPORTED_UNIX_SRR;
    }
    if ($name['type'] == UNSUPPORTED) {
        $name['msg'] = 'Unsupported File Type';
    }
    return $name;
}

/**
 * Convert a string memory notation (1024K, 10M, 1G) to an integer byte
 *
 * @param string $val
 *    Pass in value of memory.  Either an integer or integer with a measurement (g, m, k)
 *
 * @return integer
 *    Returns the amount of member in bytes being
 */
function return_bytes($val)
{
    $val         = trim($val);
    $measurement = strtolower(substr($val, -1));
    $val         = (int) substr($val, 0, -1);
    switch ($measurement) {
        case 't':
            $val *= 1024;
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }

    return $val;
}

/**
 * Function to query and find a target based on a hostname or IP.  If not found will create the target
 *
 * @param mysqli $db
 *    The mysqli connection
 * @param integer $steid
 *    The ST&E that we are operating in
 * @param string $hostname
 *    The hostname of the target being searched for
 * @param string $ip
 *    The IP address of the target being searched for
 *
 * @return integer
 *    The target ID for any targets found or created
 */
function get_a_tgt_id($db, $steid, $hostname, $ip)
{
    # gets a target ID for the hostname/ip combo
    $tgt_id = $db->check_Target($steid, $hostname);
    if (!$tgt_id) {
        $tgt_id = $db->check_Target($steid, $ip);
    }
    # If it doesn't exist, we'll have to create a target.
    # OS for MBSA is Windows, but probably use generic if we have to add a host.
    #$tgt_id = 0;
    if (!$tgt_id) {
        $sw      = $db->get_Software("cpe:/o:generic:generic:-")[0];
        $tgt_id  = $db->save_Target('insert', array(
            'ste'         => $steid,
            'osSoftware'  => $sw->get_ID(),
            'DeviceName'  => $hostname,
            'location'    => '',
            'targetNotes' => 'Created by MBSA Parser'
        ));
        $new_int = array(
            'action'   => 'insert',
            'tgt_id'   => $tgt_id,
            'ipv4'     => $ip,
            'hostname' => $hostname,
            'fqdn'     => $hostname,
        );
        $db->save_Interface($new_int);
    }
    Sagacity_Error::err_handler("Target ID: $tgt_id");
    return $tgt_id;
}

/**
 * Clean up passed in string
 *
 * @param string $string
 *
 * @return string
 */
function textCleanup($string)
{
    return htmlentities(preg_replace('/\n+/', '\n', preg_replace('/\r|\t|^\n$/', "", $string)));
}

/**
 * Function to assist in the creation and appending of XML elements to an XML DOM Document
 *
 * @param DOMDocument $xml
 *    The DOMDocument to add the element to
 * @param string $element_name
 *    The name of the element/tag to create
 * @param string $element_value
 *    The element value
 * @param boolean $is_cdata
 *    Is the value supposed to be inside a CData section
 * @param array $attrs
 *    Array of name/value pair attributes
 *
 * @return DOMElement
 *    The returned element (can be passed into appendChild)
 */
function xml_helper(&$xml, $element_name, $element_value = null, $is_cdata = false, $attrs = array())
{
    if (false) {
        $xml = new DOMDocument();
    }
    if (!is_null($element_value)) {
        if ($is_cdata) {
            $cdata = $xml->createCDATASection($element_value);
            $el    = $xml->createElement($element_name);
            $el->appendChild($cdata);
        }
        else {
            $el = $xml->createElement($element_name, $element_value);
        }
    }
    else {
        $el = $xml->createElement($element_name);
    }
    if (is_array($attrs) && count($attrs)) {
        foreach ($attrs as $name => $value) {
            $el->setAttribute($name, $value);
        }
    }
    return $el;
}

/**
 * Function to log to the time log file
 *
 * @param resource $fh
 *    File handle of the file to output too
 * @param string $msg
 *    Message to send to the file
 */
function time_log_diff($fh, $msg)
{
    global $last_time;
    //$now = new DateTime();
    $now        = microtime(true);
    $diff       = $now - $last_time;
    //if($diff > 1) {
    $lt_format  = DateTime::createFromFormat("U.u", $last_time);
    $now_format = DateTime::createFromFormat("U.u", $now);
    if (is_a($lt_format, 'DateTime') && is_a($now_format, 'DateTime')) {
        fwrite($fh, $lt_format->format("H:i:s.u") . "," . $now_format->format("H:i:s.u") . ",\"$msg\"," . round($diff, 6) . PHP_EOL);
    }
    //}
    $last_time = $now;
}

/**
 * Function to download a file from a remote server
 *
 * @param string $url
 * @param string $newname [optional]
 * @param db_helper $db [optional]
 * @param string $db_meta [optional]
 */
function download_file($url, $newname = null, &$db = null, $db_meta = null)
{
    if (!url_exists($url)) {
        Sagacity_Error::err_handler("Could not find the URL $url", E_WARNING);
        return;
    }

    $total_size = remote_filesize($url);

    if (!is_null($newname)) {
        $fname = $newname;
    }
    else {
        $fname = basename($url);
    }

    if (!($local_fh = fopen($fname, "w"))) {
        Sagacity_Error::err_handler("Failed to open the local file handle" . PHP_EOL, E_ERROR);
    }

    if (!($remote_fh = fopen($url, "r"))) {
        Sagacity_Error::err_handler("Was not able to open the file $url", E_ERROR);
    }

    $written_size = 0;
    print "Downloading $url (" . human_filesize($total_size) . ")" . PHP_EOL;
    //$start = microtime();
    while ($data         = fread($remote_fh, 1048576)) {
        //$end = microtime();
        fwrite($local_fh, $data);
        $written_size += strlen($data);
        $complete     = ($written_size / $total_size) * 100;

        print "\rComplete " . sprintf("%.2f%%", $complete);

        if (is_a($db, 'db_helper') && !is_null($db_meta) && strlen($db_meta)) {
            $db->update("sagacity.settings", ['meta_value' => number_format($complete, 2)], [
                [
                    'field' => 'meta_key',
                    'op'    => '=',
                    'value' => $db_meta
                ]
            ]);
            $db->execute();
        }
    }

    print PHP_EOL;
}

/**
 * To convert the byte size of a file to a human readable format
 *
 * @param int $bytes
 * @param int $decimals
 *
 * @return string
 */
function human_filesize($bytes, $decimals = 2)
{
    $sz     = 'BKMGTP';
    $factor = floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor];
}

/**
 * To get the remote file size (returns bytes)
 *
 * @param string $url
 *
 * @return boolean|int
 */
function remote_filesize($url)
{
    error_reporting(E_ERROR);
    try {
        if ($size = filesize($url)) {
            return $size;
        }
    }
    catch (Exception $e) {

    }

    $regex   = "/Content\-Length: *([\d]+)/i";
    $matches = array();
    if (!$fp      = @fopen($url, 'rb')) {
        return false;
    }
    if (
        isset($http_response_header) &&
        preg_match_all($regex, implode(PHP_EOL, $http_response_header), $matches)
    ) {
        if (count($matches[0])) {
            return (int) max($matches[1]);
        }
    }

    print "Could not find the content-length in the header, so downloading the file to get the length" . PHP_EOL;
    return strlen(stream_get_contents($fp));
}

/**
 * Function to replace only the first instance of a string
 *
 * @param string $search
 * @param string $replace
 * @param string $subject
 *
 * @return string
 */
function str_replace_first($search, $replace, $subject)
{
    return implode($replace, explode($search, $subject, 2));
}

/**
 * Function to check for the existence of a path and create a directory if not found
 *
 * @param string $path
 * @param boolean $chdir
 */
function check_path($path, $chdir = false)
{
    if (!file_exists($path)) {
        try {
            // come in 4 characters from the end and check to see if it is a . (period), which signifies a file was passed in
            if (strpos($path, ".") !== false && substr($path, -4, 1) == '.' || substr($path, -6, 1) == '.') {
                touch($path);
            }
            else {
                mkdir($path);
            }
        }
        catch (Exception $e) {
            die($e->getMessage());
        }
    }

    if ($chdir && is_dir($path)) {
        chdir($path);
    }
}

/**
 * To create a bzip file
 *
 * @param string $in
 * @param string $out
 *
 * @return bool
 */
function bzip2($in, $out)
{
    if (!file_exists($in) || !is_readable($in))
        return false;
    if ((!file_exists($out) && !is_writeable(dirname($out)) || (file_exists($out) && !is_writable($out))))
        return false;
    if (!function_exists("bzopen"))
        return false;

    $in_file  = fopen($in, "r");
    $out_file = bzopen($out, "w");

    while (!feof($in_file)) {
        $buffer = fgets($in_file, 4096);
        bzwrite($out_file, $buffer, 4096);
    }

    fclose($in_file);
    bzclose($out_file);

    return true;
}

/**
 * To unzip a bzip file
 *
 * @param string $in
 * @param string $out
 *
 * @return bool
 */
function bunzip2($in, $out)
{
    if (!file_exists($in) || !is_readable($in))
        return false;
    if ((!file_exists($out) && !is_writeable(dirname($out)) || (file_exists($out) && !is_writable($out))))
        return false;
    if (!function_exists("bzopen"))
        return false;

    $in_file  = bzopen($in, "r");
    $out_file = fopen($out, "w");

    while ($buffer = bzread($in_file, 4096)) {
        fwrite($out_file, $buffer, 4096);
    }

    bzclose($in_file);
    fclose($out_file);

    return true;
}

/**
 * Function to ping a host and respond boolean
 *
 * @param string $host
 * @param int $port
 * @param int $timeout
 *
 * @return boolean
 */
function ping($host, $port = 80, $timeout = 6)
{
    //$e = new Exception("Test");
    //die($e->getTraceAsString());
    $errno  = null;
    $errstr = null;
    $fsock  = @fsockopen($host, $port, $errno, $errstr, $timeout);
    if (is_resource($fsock)) {
        return true;
    }
    return false;
}

/**
 * To evaluate $val and see if it is between low and high values inclusively.
 *
 * @param number $val
 *    The value to check
 * @param number $low
 *    The minimum allowed value
 * @param number $high
 *    The maximum allowed value
 *
 * @return boolean
 */
function between($val, $low, $high)
{
    if (is_numeric($val) && is_numeric($low) && is_numeric($high)) {
        if ($val >= $low && $val <= $high) {
            return true;
        }
    }

    return false;
}

/**
 * Function to check if a URL exists (run prior to downloading a file)
 *
 * @param string $url
 *
 * @return boolean
 */
function url_exists($url)
{
    $file_headers = get_headers($url);
    foreach ($file_headers as $header) {
        if (preg_match("/HTTP\/[\d\.]+ 200 OK/", $header)) {
            return true;
        }
    }

    return false;
}

/**
 *
 * @param float $start
 * @param float $end
 * @return float
 */
function microtime_diff($start, $end = null)
{
    list($start_usec, $start_sec) = explode(" ", $start);
    list($end_usec, $end_sec) = explode(" ", $end);

    $diff_sec  = intval($end_sec) - intval($start_sec);
    $diff_usec = floatval($end_usec) - floatval($start_usec);

    return floatval($diff_sec) + $diff_usec;
}

/**
 * Sagacity encryption algorithm
 *
 * @param string $data
 * @param string $salt
 *
 * @return string
 */
function my_encrypt($data, $salt = null)
{
    // Remove the base64 encoding from our key
    if (is_null($salt)) {
        $encryption_key = base64_decode(SALT);
    }
    else {
        $encryption_key = base64_decode($salt);
    }
    // Generate an initialization vector
    $iv        = openssl_random_pseudo_bytes(openssl_cipher_iv_length(ALGORITHM));
    // Encrypt the data using AES 256 encryption in CBC mode using our encryption key and initialization vector.
    $encrypted = openssl_encrypt($data, ALGORITHM, $encryption_key, 0, $iv);
    // The $iv is just as important as the key for decrypting, so save it with our encrypted data using a unique separator (::)
    return base64_encode($encrypted . '::' . $iv);
}

/**
 * Sagacity decryption algorithm
 *
 * @param string $data
 * @param string $key
 *
 * @return string
 */
function my_decrypt($data)
{
    // Remove the base64 encoding from our key
    $encryption_key = base64_decode(SALT);
    // To decrypt, split the encrypted data from our IV - our unique separator used was "::"
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, ALGORITHM, $encryption_key, 0, $iv);
}

/**
 * Sagacity method to replace string by reference
 *
 * @param string $search
 * @param string $replace
 * @param string &$subject
 */
function my_str_replace($search, $replace, &$subject)
{
    $subject = str_replace($search, $replace, $subject);
}

/**
 * Helper method to add DateIntervals
 *
 * @param DateInterval $i1
 * @param DateInterval $i2
 *
 * @return DateInterval
 */
function add_intervals($i1, $i2)
{
    $a = new DateTime("00:00");
    $b = clone $a;

    if (is_a($i1, 'DateInterval')) {
        $a->add($i1);
    }

    if (is_a($i2, 'DateInterval')) {
        $a->add($i2);
    }

    return $b->diff($a);
}

/**
 * Helper method to convert a file name to a .log file
 *
 * @param string $fname
 *
 * @return string New filename with the prepended LOG_PATH
 */
function logify($fname)
{
    $fname = preg_replace("/[\.][^\.]+$/", '', basename($fname));
    if (!file_exists(LOG_PATH . "/{$fname}.log")) {
        touch(LOG_PATH . "/{$fname}.log");
    }

    return LOG_PATH . "/{$fname}.log";
}

/**
 * Helper method to convert LOG_LEVEL to Logger PSR log level
 *
 * @return string
 */
function convert_log_level()
{
    switch (LOG_LEVEL) {
        case E_DEBUG:
            return Logger::DEBUG;
        case E_NOTICE:
            return Logger::NOTICE;
        case E_WARNING:
            return Logger::WARNING;
        default:
            return Logger::ERROR;
    }
}
