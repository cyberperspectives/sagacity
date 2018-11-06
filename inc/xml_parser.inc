<?php
/**
 * File: xml_parser.inc
 * Author: Ryan Prather
 * Purpose: Contain stream based XML parsers
 * Created: Oct 17, 2014
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
 *  - Oct 17, 2014 - File created
 *  - Sep 3, 2016 - Copyright and file purpose updated, and
 * 					updated function calls after class merger
 *  - Oct 24, 2016 - Renamed XMLParser class to scan_xml_parser
 * 					 Added several PHP_DOC comments
 *  - Nov 7, 2016 - Added PHP_DOC comment, moved call_user_func functions inside try...catch blocks, and cleaned up debugging statements
 *  - Feb 15, 2017 - Formatting
 *  - Mar 22, 2017 - Added check for $this->scan type before destruction to fix error in failures
 *  - Apr 5, 2017 - Fixed bug with source type
 */
include_once 'database.inc';

/**
 * Root class to do all XML stream parsing
 */
class scan_xml_parser
{

    /**
     * Boolean to decide if we are debugging the parser script
     *
     * @var boolean
     */
    var $debug;

    /**
     * The raw parser object to read the XML
     *
     * @var mixed
     */
    var $parser;

    /**
     * The database connection for use by the parser
     *
     * @var db
     */
    var $db;

    /**
     * The ST&amp;E ID that result file is being import into
     *
     * @var int
     */
    var $ste_id;

    /**
     * The object that will do the grunt of the parsing
     *
     * @var mixed
     */
    var $obj;

    /**
     * The stack that is used to check for a parser function
     *
     * @var array:string
     */
    var $stack;

    /**
     * The tag ID.  This stores of the "ID" element from the tag being parsed
     *
     * @var string
     */
    var $tag_id;

    /**
     * The scan object that is created as a result of this file
     *
     * @var scan
     */
    var $scan;

    /**
     * The logger
     *
     * @var Sagacity_Error
     */
    var $log;

    /**
     * Array of targets found in the result file and the count of findings for that target
     *
     * @var array
     */
    var $host_list;

    /**
     * Temp holder for the target finding count until it is added to the $host_list array
     *
     * @var int
     */
    var $tgt_finding_count;

    /**
     * Array of findings that have never been found before
     *
     * @var array:finding
     */
    var $new_findings;

    /**
     * Array of findings that have been seen before
     *
     * @var array:finding
     */
    var $updated_findings;

    /**
     * Boolean to decide if a plugin is skipped
     *
     * @var boolean
     */
    var $skip = false;

    /**
     * The file being parsed
     *
     * @var string
     */
    var $file = '';

    /**
     * The basename of the file being parsed
     *
     * @var string
     */
    var $base_name = '';

    /**
     * The size of the file
     *
     * @var int
     */
    var $file_size = 0;

    /**
     * The file handle of the scan file that's parsed
     *
     * @var resource
     */
    var $fh = null;

    /**
     * The file handler for the time log file to analyze performance
     *
     * @todo Make sure disabled for each release
     *
     * @var resource
     */
    var $time_log_fh = null;

    /**
     * The last time the time log was called
     *
     * @var mixed
     */
    var $last_time;

    /**
     * The previous stack element
     *
     * @var string
     */
    var $previous = null;

    /**
     * Shows the type of result file this is
     *
     * @var string
     */
    var $type = null;

    /**
     * Construct
     *
     * @param mixed $obj_in
     * @param int $ste_id_in
     * @param string $scan_fname
     */
    function __construct($obj_in, $ste_id_in, $scan_fname)
    {
        $this->log = new Sagacity_Error($scan_fname);

        $this->parser = xml_parser_create();
        xml_set_object($this->parser, $this);
        xml_set_element_handler($this->parser, "startElement", "stopElement");
        xml_set_character_data_handler($this->parser, "characterData");
        xml_parser_set_option($this->parser, XML_OPTION_CASE_FOLDING, 0);

        $this->debug       = (LOG_LEVEL == E_DEBUG ? true : false);
        $this->db          = new db();
        $this->ste_id      = $ste_id_in;
        $this->obj         = $obj_in;
        $this->stack       = array();
        $this->file_size   = filesize($scan_fname);
        $this->base_name   = basename($scan_fname);
        $this->file        = $scan_fname;
        $time_log_fname    = preg_replace("/[\.][^\.]+$/", '', basename($scan_fname)) . "-timelog.csv";
        $this->time_log_fh = fopen(realpath(LOG_PATH) . "/$time_log_fname", "w");
        $this->last_time   = microtime(true);

        $match = array();

        if (is_a($this->obj, "nessus_parser")) {
            $src = $this->db->get_Sources("Nessus");
        }
        elseif (is_a($this->obj, "scc_parser")) {
            $src = $this->db->get_Sources("SCC XCCDF");

            preg_match('/\_SCC-(\d\.?)+\_(\d{4}\-\d{2}\-\d{2}\_\d{6})\_XCCDF/', $this->file, $match);
            $time_stamp = $match[2];
        }
        elseif (is_a($this->obj, "mssql_parser")) {
            $src = $this->db->get_Sources("mssql");
        }

        if (is_array($src) && count($src) && isset($src[0]) && is_a($src[0], 'source')) {
            $src = $src[0];
        }

        if (isset($time_stamp)) {
            $mtime = DateTime::createFromFormat('Y-m-d_His', $time_stamp);
        }
        else {
            $mtime = DateTime::createFromFormat("U", filemtime($scan_fname));
        }

        $this->scan = $this->db->get_ScanData($this->ste_id, $this->base_name);
        if (is_array($this->scan) && count($this->scan)) {
            $this->scan = $this->scan[0];
            $this->scan->inc_Itr();
        }
        else {
            $ste        = $this->db->get_STE($this->ste_id)[0];
            $this->scan = new scan(null, $src, $ste, 1, $this->base_name, $mtime->format("Y-m-d H:i:s"));

            if (!$scan_id = $this->db->save_Scan($this->scan)) {
                $this->log->script_log("Error adding scan", E_ERROR);
            }

            $this->scan->set_ID($scan_id);
        }
    }

    /**
     * Destructor
     */
    function __destruct()
    {
        if (is_a($this->scan, 'scan')) {
            $this->db->save_Scan($this->scan);
            if ($this->scan->get_Status() != "TERMINATED") {
                $this->db->update_Running_Scan($this->base_name, array('name' => 'perc_comp', 'value' => 100, 'complete' => 1));
            }
        }

        if (!$this->debug && $this->type && $this->base_name && file_exists($this->file) && $this->scan->get_Status() != 'TERMINATED') {
            rename($this->file, TMP . "/{$this->type}/$this->base_name");
        }
    }

    /**
     * Function to parse start element tags and attributes
     *
     * @param mixed $parser
     *    The object that created this parser
     * @param string $name
     *    The element name (what's between the <>)
     * @param array:string $attrs
     *    Name/value pair array of attributes
     */
    function startElement($parser, $name, $attrs)
    {
        $this->db->is_Connected();
        $this->stack[] = str_replace("-", "_", str_replace(":", "_", $name));
        if (method_exists($this->obj, implode("_", $this->stack)) && !$this->skip) {
            //print implode("_", $this->stack)." exists\n";
            if ($this->debug)
                $this->log->script_log("START function " . implode("_", $this->stack), E_DEBUG);
            try {
                call_user_func(array($this->obj, implode("_", $this->stack)), $attrs);
            }
            catch (Exception $e) {
                $this->log->script_log("Error processing start function for " . implode("_", $this->stack) . "\n{$e->__toString()}", E_ERROR);
            }
            if ($this->debug)
                $this->log->script_log("END START function " . implode("_", $this->stack), E_DEBUG);
        }
        elseif ($this->skip) {
            if ($this->debug) {
                $this->log->script_log("skipping id " . $this->tag_id);
            }
        }
        else {
            //print implode("_", $this->stack)." doesn't exist\n";
        }
    }

    /**
     * Function to parse the stop element tag
     *
     * @param mixed $parser
     *    The parser object that is doing the parsing
     * @param string $name
     *    The element tag name
     */
    function stopElement($parser, $name)
    {
        $this->check_status();

        $this->db->is_Connected();
        if (method_exists($this->obj, implode("_", $this->stack) . "_end")) {
            //print implode("_", $this->stack)."_end exists\n";
            // update progress
            $cur_pos = xml_get_current_byte_index($this->parser);
            $this->db->update_Running_Scan($this->scan->get_File_Name(), array("name" => "perc_comp", "value" => ($cur_pos / $this->file_size) * 100));

            // call function
            if ($this->debug)
                $this->log->script_log("STOP function " . implode("_", $this->stack) . "_end", E_DEBUG);
            try {
                call_user_func(array($this->obj, implode("_", $this->stack) . "_end"));
            }
            catch (Exception $e) {
                $this->log->script_log("Error processing end function for " . implode("_", $this->stack) . "\n{$e->__toString()}", E_ERROR);
            }
            if ($this->debug)
                $this->log->script_log("END STOP function " . implode("_", $this->stack) . "_end", E_DEBUG);
        }
        else {
            //print implode("_", $this->stack)."_end doesn't exist\n";
        }
        array_pop($this->stack);
    }

    /**
     * Function to parse the interior contents of the element
     *
     * @param mixed $parser
     * @param string $data
     */
    function characterData($parser, $data)
    {
        $this->db->is_Connected();
        if (method_exists($this->obj, implode("_", $this->stack) . "_data") && !$this->skip) {
            //print implode("_", $this->stack)."_data exists\n";
            if ($this->debug)
                $this->log->script_log("DATA function " . implode("_", $this->stack) . "_data\n$data", E_DEBUG);
            try {
                call_user_func(array($this->obj, implode("_", $this->stack) . "_data"), $data);
            }
            catch (Exception $e) {
                $this->log->script_log("Error processing data function for " . implode("_", $this->stack) . "\n{$e->__toString()}", E_ERROR);
            }
            if ($this->debug)
                $this->log->script_log("END DATA function " . implode("_", $this->stack) . "_data", E_DEBUG);
        }
        else {
            //print implode("_", $this->stack)."_data doesn't exist\n";
        }
    }

    /**
     * The parsing function that does all the file reading
     */
    function parse()
    {
        $this->db->update_Running_Scan($this->base_name, array('name' => 'pid', 'value' => getmypid()));

        $this->fh = fopen($this->file, "r");
        while ($data     = fread($this->fh, 4096)) {
            try {
                if (!xml_parse($this->parser, $data, feof($this->fh)) && !xml_get_error_code($this->parser)) {
                    $this->log->script_log(xml_error_string(xml_get_error_code($this->parser)), E_ERROR);
                }
            }
            catch (Exception $e) {
                $this->log->script_log("Error parsing file \n{$e->__toString()}", E_ERROR);
            }
        }
        fclose($this->fh);
        xml_parser_free($this->parser);
    }

    /**
     * A function to log the time differences for performance troubeshooting
     *
     * @param string $msg
     *    The message to output the file
     * @param string $function (optional)
     *    The function
     */
    function time_log_diff($msg, $function = null)
    {
        if (is_null($function)) {
            $function = implode("_", $this->stack);
        }
        $now  = microtime(true);
        $diff = $now - $this->last_time;

        if ($this->debug || $diff > 3) {
            $lt_dt  = DateTime::createFromFormat("U.u", $this->last_time);
            $now_dt = DateTime::createFromFormat("U.u", $now);

            if (is_a($lt_dt, "DateTime") && is_a($now_dt, "DateTime")) {
                fputcsv($this->time_log_fh, array(
                    $lt_dt->format("H:i:s.u"),
                    $now_dt->format("H:i:s.u"),
                    $msg,
                    $this->previous,
                    $function,
                    round($diff, 6)
                ));
            }
        }

        $this->previous  = $function;
        $this->last_time = $now;
    }

    /**
     * Function to check the status of the scan thread, if the status is TERMINATED it will kill the thread
     */
    private function check_status()
    {
        $this->db->help->select("sagacity.scans", array('status'), array(
            array(
                'field' => 'id',
                'op'    => '=',
                'value' => $this->scan->get_ID()
            )
        ));
        $thread_status = $this->db->help->execute();

        if ($thread_status['status'] == 'TERMINATED') {
            unset($this->parser);

            $this->scan->set_Status("TERMINATED");
            for ($x = 0; $x < 3; $x++) {
                if (fclose($this->fh)) {
                    $this->fh = null;
                    $x        = 2;
                }
                usleep(100000);
            }

            rename(realpath(TMP . "/{$this->scan->get_File_Name()}"), TMP . "/terminated/{$this->scan->get_File_Name()}");
            $this->log->script_log("File parsing terminated by user");
            die();
        }
    }
}

class basic_xml_parser
{

    var $debug;
    var $parser;
    var $db;
    var $obj;
    var $stack;
    var $tag_id;
    var $log;
    var $file        = '';
    var $base_name   = '';
    var $file_size   = 0;
    var $time_log_fh = null;
    var $last_time;
    var $pos         = 0;
    var $skip        = false;
    var $previous    = null;

    function __construct($obj_in, $xml_fname)
    {
        $this->parser = xml_parser_create();
        xml_set_object($this->parser, $this);
        xml_set_element_handler($this->parser, "startElement", "stopElement");
        xml_set_character_data_handler($this->parser, "characterData");
        xml_parser_set_option($this->parser, XML_OPTION_CASE_FOLDING, 0);

        $this->db          = new db();
        $this->obj         = $obj_in;
        $this->stack       = array();
        $this->log         = new Sagacity_Error($xml_fname);
        $this->file_size   = filesize($xml_fname);
        $this->base_name   = basename($xml_fname);
        $this->file        = $xml_fname;
        $time_log_fname    = preg_replace("/[\.][^\.]+$/", '', $this->base_name) . "-timelog.csv";
        $this->time_log_fh = fopen(realpath(LOG_PATH) . "/$time_log_fname", "w");
        $this->last_time   = microtime(true);
    }

    function __destruct()
    {

    }

    function startElement($parser, $name, $attrs)
    {
        $this->stack[] = str_replace("-", "_", str_replace(":", "_", $name));
        if (method_exists($this->obj, implode("_", $this->stack)) && !$this->skip) {
            //print implode("_", $this->stack)." exists\n";
            $this->pos = xml_get_current_byte_index($this->parser);

            if ($this->debug)
                $this->time_log_diff("START function");

            call_user_func(array($this->obj, implode("_", $this->stack)), $attrs);

            if ($this->debug)
                $this->time_log_diff("END START function");
        }
        elseif ($this->skip) {
            if ($this->debug) {
                $this->log->script_log("skipping id " . $this->tag_id);
            }
        }
        else {
            //print implode("_", $this->stack)." doesn't exist\n";
        }
    }

    function stopElement($parser, $name)
    {
        if (method_exists($this->obj, implode("_", $this->stack) . "_end")) {
            //print implode("_", $this->stack)."_end exists\n";
            // update progress
            $this->pos = xml_get_current_byte_index($this->parser);
            //$this->db->update_Running_Scan($this->scan->get_File_Name(), array("name"=>"perc_comp","value"=>($this->pos/$this->file_size)*100));
            // call function
            if ($this->debug)
                $this->time_log_diff("STOP function", implode("_", $this->stack) . "_end");
            call_user_func(array($this->obj, implode("_", $this->stack) . "_end"));
            if ($this->debug)
                $this->time_log_diff("END STOP function", implode("_", $this->stack) . "_end");
        }
        else {
            //print implode("_", $this->stack)."_end doesn't exist\n";
        }
        array_pop($this->stack);
    }

    function characterData($parser, $data)
    {
        if (method_exists($this->obj, implode("_", $this->stack) . "_data") && !$this->skip) {
            //print implode("_", $this->stack)."_data exists\n";
            $this->pos = xml_get_current_byte_index($this->parser);

            if ($this->debug)
                $this->time_log_diff("DATA function", implode("_", $this->stack) . "_data");
            call_user_func(array($this->obj, implode("_", $this->stack) . "_data"), $data);
            if ($this->debug)
                $this->time_log_diff("END DATA function", implode("_", $this->stack) . "_data");
        }
        else {
            //print implode("_", $this->stack)."_data doesn't exist\n";
        }
    }

    function parse()
    {
        $fh   = fopen($this->file, "r");
        while ($data = fread($fh, 4096)) {
            if (!xml_parse($this->parser, $data, feof($fh)) && !xml_get_error_code($this->parser)) {
                print_r($this->stack);
                $this->log->script_log(xml_error_string(xml_get_error_code($this->parser)), E_WARNING);
            }
        }
        fclose($fh);
        xml_parser_free($this->parser);
    }

    function time_log_diff($msg, $function = null)
    {
        if (is_null($function)) {
            $function = implode("_", $this->stack);
        }
        $now  = microtime(true);
        $diff = $now - $this->last_time;

        if ($this->debug || $diff > 3) {
            $lt_dt  = DateTime::createFromFormat("U.u", $this->last_time);
            $now_dt = DateTime::createFromFormat("U.u", $now);

            if (is_a($lt_dt, "DateTime") && is_a($now_dt, "DateTime")) {
                fputcsv($this->time_log_fh, array(
                    $lt_dt->format("H:i:s.u"),
                    $now_dt->format("H:i:s.u"),
                    $msg,
                    $this->previous,
                    $function,
                    round($diff, 6)
                ));
            }
        }

        $this->previous  = $function;
        $this->last_time = $now;
    }
}
