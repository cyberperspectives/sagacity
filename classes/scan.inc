<?php
/**
 * File: scan.inc
 * Author: Ryan Prather
 * Purpose: Represents an imported scan
 * Created: Sep 12, 2013
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
 *  - Sep 12, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright and Merge result_script & scan classes
 *  - Oct 24, 2016 - Updated function headers and format
 *  - Nov 7, 2016 - Make sure get_Total_Host_Count() returns an integer
 *  - Apr 5, 2017 - Formatting
 *  - Jan 16, 2018 - Updated to use host_list class
 */
define("IN_QUEUE", "IN QUEUE");
define("RUNNING", "RUNNING");
define("COMPLETE", "COMPLETE");
define("ERROR", "ERROR");
define("TERMINIATED", "TERMINATED");

require_once 'host_list.inc';

/**
 * Represents an imported scan
 *
 * @author Ryan Prather
 */
class scan
{

    /**
     * Scan ID
     *
     * @var integer
     */
    protected $id = 0;

    /**
     * Source
     *
     * @var source
     */
    protected $src = null;

    /**
     * ST&E
     *
     * @var ste
     */
    protected $ste = null;

    /**
     * Interation (in case the same scan is imported multiple times)
     *
     * @var integer
     */
    protected $itr = 0;

    /**
     * File name of the imported file
     *
     * @var string
     */
    protected $file_name = '';

    /**
     * File date of the imported file (for configuration management)
     *
     * @var string
     */
    protected $file_date = '';

    /**
     * Array of hosts
     *
     * @var array:host_list
     */
    protected $host_list = array();

    /**
     * Scan notes
     *
     * @var string
     */
    protected $notes = '';

    /**
     * Process ID (PID) of the executing script
     *
     * @var integer
     */
    protected $pid = 0;

    /**
     * Enum defining the type of script
     *
     * @var string
     */
    protected $type = null;

    /**
     * Date/time the script started
     *
     * @var DateTime
     */
    protected $start_time = null;

    /**
     * Date/time the script was updated
     *
     * @var DateTime
     */
    protected $last_update = null;

    /**
     * Enum script status
     *
     * @var string
     */
    protected $status = 0;

    /**
     * Percentage of completion
     *
     * @var float
     */
    protected $perc_comp = 0.0;

    /**
     * The last host that was imported
     *
     * @var string
     */
    protected $last_host = '';

    /**
     * Number of hosts that have been completely imported
     *
     * @var integer
     */
    protected $host_complete_count = 0;

    /**
     * Number of hosts in the result file
     *
     * @var integer
     */
    protected $host_count = 0;

    /**
     * Variable to store if there is an error in a given scan
     *
     * @var boolean
     */
    protected $scanner_error = false;

    /**
     * Constructor
     *
     * @param integer $int_ID
     * @param source $src_in
     * @param ste $ste_in
     * @param integer $int_Itr
     * @param string $str_File_Name
     * @param string $str_File_Date
     */
    public function __construct($int_ID, $src_in, $ste_in, $int_Itr, $str_File_Name, $str_File_Date)
    {
        $this->id        = $int_ID;
        $this->src       = $src_in;
        $this->ste       = $ste_in;
        $this->itr       = $int_Itr;
        $this->file_date = $str_File_Date;
        $this->file_name = $str_File_Name;
    }

    /**
     * Getter function for Id
     *
     * @return integer
     */
    public function get_ID()
    {
        return $this->id;
    }

    /**
     * Setter function for the scan ID
     *
     * @param integer $int_ID
     */
    public function set_ID($int_ID)
    {
        $this->id = $int_ID;
    }

    /**
     * Getter function for source
     *
     * @return source
     */
    public function get_Source()
    {
        return $this->src;
    }

    /**
     * Getter function for STE
     *
     * @return ste
     */
    public function get_STE()
    {
        return $this->ste;
    }

    /**
     * Getter function for iteration
     *
     * @return integer
     */
    public function get_Itr()
    {
        return $this->itr;
    }

    /**
     * Setter function to increase the iteration for this scan
     */
    public function inc_Itr()
    {
        $this->itr++;
    }

    /**
     * Getter function for file name
     *
     * @return string
     */
    public function get_File_Name()
    {
        return $this->file_name;
    }

    /**
     * Getter function for file date
     *
     * @return string
     */
    public function get_File_Date()
    {
        return $this->file_date;
    }

    /**
     * Getter function for file date in DateTime
     *
     * @return DateTime
     */
    public function get_File_DateTime()
    {
        return new DateTime($this->file_date);
    }

    /**
     * Setter function for file date
     *
     * @param string|DateTime $dt_in
     */
    public function set_File_DateTime($dt_in)
    {
        if (is_string($dt_in)) {
            $this->file_date = $dt_in;
        }
        else {
            $this->file_date = $dt_in->format("Y-m-d H:i:s");
        }
    }

    /**
     * Getter method for scanner error
     *
     * @return bool
     */
    public function isScanError()
    {
        return $this->scanner_error;
    }

    /**
     * Setter method for scanner error
     *
     * @param bool $scanError
     */
    public function setScanError(bool $scanError)
    {
        $this->scanner_error = $scanError;
    }

    /**
     * Function to add a target and finding count to the host list
     *
     * @param host_list $hl
     */
    public function add_Target_to_Host_List($hl)
    {
        $this->host_list[$hl->getTargetId()] = $hl;
    }

    /**
     * Function to replace the host list array
     *
     * @param host_list:array $host_list_in
     */
    public function add_Target_Array_to_Host_List($host_list_in)
    {
        $this->host_list = $host_list_in;
    }

    /**
     * Getter function for host list array
     *
     * @return array
     */
    public function get_Host_List()
    {
        return $this->host_list;
    }

    /**
     * Getter function for scan notes
     *
     * @return string
     */
    public function get_Notes()
    {
        return $this->notes;
    }

    /**
     * Setter function for scan notes
     *
     * @param string $notes_in
     */
    public function set_Notes($notes_in)
    {
        $this->notes = $notes_in;
    }

    /**
     * Getter function to retrieve number of hosts in the host list array
     *
     * @return integer
     */
    public function get_Host_List_Count()
    {
        return count($this->host_list);
    }

    /**
     * Getter function for pre-formatted host list table row
     *
     * @return string
     */
    public function get_Host_List_Table()
    {
        $ret      = '';
        $count    = 0;
        $findings = 0;
        foreach ($this->host_list as $host) {
            $count++;
            $findings += $host->getFindingCount();

            $ret .= "<tr>" .
                "<td>{$count}</td>" .
                "<td>{$host->getTargetName()}</td>" .
                "<td>{$host->getFindingCount()}</td>" .
                "<td>{$host->getTargetIp()}</td>" .
                "<td>" . ($host->getScanError() ? "<img src='/img/error.png' class='checklist_image' title='{$host->getScanNotes()}' />" : "") . "</td>" .
                "</tr>";
        }

        return [
            $findings,
            $ret
        ];
    }

    /**
     * Getter function for the process ID
     *
     * @return int
     */
    public function get_PID()
    {
        return ($this->pid ? $this->pid : 0);
    }

    /**
     * Setter function for the process ID
     *
     * @param int $pid_in
     */
    public function set_PID($pid_in)
    {
        $this->pid = $pid_in;
    }

    /**
     * Getter function for the scan type
     *
     * @return string
     */
    public function get_Type()
    {
        return $this->type;
    }

    /**
     * Setter function for the scan type
     *
     * @param string $type_in
     */
    public function set_Type($type_in)
    {
        $this->type = $type_in;
    }

    /**
     * Getter function for the start date/time of the script
     *
     * @return DateTime
     */
    public function get_Start_Time()
    {
        if (!is_a($this->start_time, "DateTime")) {
            return new DateTime();
        }
        return $this->start_time;
    }

    /**
     * Setter function for the start date/time of the script
     *
     * @param DateTime $start_time_in
     */
    public function set_Start_Time($start_time_in)
    {
        if (is_a($start_time_in, "DateTime")) {
            $this->start_time = $start_time_in;
        }
        else {
            $this->start_time = new DateTime($start_time_in);
        }
    }

    /**
     * Getter function for the last update of the script
     *
     * @return DateTime
     */
    public function get_Last_Update()
    {
        if (!is_a($this->last_update, "DateTime")) {
            return new DateTime();
        }
        return $this->last_update;
    }

    /**
     * Setter function for the last update DateTime the script was updated
     *
     * @param DateTime $last_update_in
     */
    public function set_Last_Update($last_update_in)
    {
        if (is_a($last_update_in, "DateTime")) {
            $this->last_update = $last_update_in;
        }
        else {
            $this->last_update = new DateTime($last_update_in);
        }
    }

    /**
     * Getter function for the script status
     *
     * @return string
     */
    public function get_Status()
    {
        return $this->status;
    }

    /**
     * Setter function for the script status
     *
     * @param string $status_in
     */
    public function set_Status($status_in)
    {
        $this->status = $status_in;
    }

    /**
     * Method to check if the scan has been terminated by the user
     */
    public function isTerminated()
    {
        global $db, $log;
        $db->help->select("scans", ['status'], [
            [
                'field' => 'id',
                'op'    => '=',
                'value' => $this->id
            ]
        ]);
        $thread_status = $db->help->execute();

        $this->status = $thread_status['status'];

        if ($this->status == TERMINIATED) {
            rename(realpath(TMP . "/{$this->file_name}"), TMP . "/terminated/{$this->file_name}");
            $log->notice("File parsing terminated by user");
            die();
        }
    }

    /**
     * Getter function for the percentage the script has completed
     *
     * @return float
     */
    public function get_Percentage_Complete()
    {
        return number_format($this->perc_comp, 2);
    }

    /**
     * Setter function for the percentage the script has completed
     *
     * @param float $perc_comp_in
     */
    public function set_Percentage_Complete($perc_comp_in)
    {
        $this->perc_comp = $perc_comp_in;
    }

    /**
     * Getter function for the last host the scan completed parsing
     *
     * @return string
     */
    public function get_Last_Host()
    {
        return $this->last_host;
    }

    /**
     * Setter function for the last host that the scan completed
     *
     * @param string $last_host_in
     */
    public function set_Last_Host($last_host_in)
    {
        $this->last_host = $last_host_in;
    }

    /**
     * Getter function for the number of hosts complete
     *
     * @return int
     */
    public function get_Host_Complete_Count()
    {
        return $this->host_complete_count;
    }

    /**
     * Increment the number of hosts complete
     */
    public function inc_Host_Complete_Count()
    {
        $this->host_complete_count++;
    }

    /**
     * Getter function for the number of hosts in the scan file
     *
     * @return int
     */
    public function get_Total_Host_Count()
    {
        return ($this->host_count ? $this->host_count : 0);
    }

    /**
     * Setter function for the total host in the scan file
     *
     * @param int $total_host_count_in
     */
    public function set_Total_Host_Count($total_host_count_in)
    {
        $this->host_count = $total_host_count_in;
    }
    
    /**
     * Method to set a host error
     * 
     * @param int $tgt_id
     * @param boolean $is_error
     * @param string $err_msg
     */
    public function set_Host_Error($tgt_id, $is_error, $err_msg = null)
    {
        foreach($this->host_list as $x => $h) {
            /** @var host_list $h */
            if($h->getTargetId() == $tgt_id) {
                $this->host_list[$x]->setScanError($is_error);
                $this->host_list[$x]->setScanNotes($err_msg);
                break;
            }
        }
    }

    /**
     * Function to return string of the td row for the upload progress page
     *
     * @return string
     */
    public function get_Task_Row()
    {
        $ret = "<tr id='" . str_replace([" ", "(", ")"], ["_", "", ""], $this->file_name) . "'>" .
            "<td>{$this->src->get_Name()}</td>" .
            "<td>{$this->file_name}</td>" .
            "<td>{$this->start_time->format("H:i:s")}</td>" .
            "<td>{$this->last_update->format("H:i:s")}</td>" .
            "<td>{$this->status}</td>" .
            "<td><progress max='100' value='{$this->perc_comp}' data-value='{$this->perc_comp}'></progress></td>" .
            "<td></td>" .
            "</tr>";

        return $ret;
    }
}
