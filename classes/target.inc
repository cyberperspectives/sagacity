<?php
/**
 * File: target.inc
 * Author: Ryan Prather
 * Purpose: Represent a target that needs to be scanned
 * Created: Sep 12, 2013
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
 *  - Sep 12, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright and added comments
 *  - Oct 10, 2016 - Added get_JSON function to support change in ajax.php
 *  - Nov 7, 2016 - Added append_Notes function
 *  - Jan 30, 2017 - Removed task status from get_JSON function return (only used in new-ops.php)
 *  - Apr 11, 2017 - Changed statuses to default to null instead of '0' which is not valid in the DB
 *  - Dec 27, 2017 - Updated syntax
 *  - Jan 10, 2018 - Added cat_1/2/3, nr, na, nf variables to store finding counts (and getter setter methods)
 *                   And calculation methods for compliance and assessment percentages
 *  - Jan 15, 2018 - Added getDisplayNotes method and updated getAssessedPercent and getCompliantPercent to return float instead of string
 *  - Jan 16, 2018 - Added getIP method to return first non-loopback, non-0 IP address
 */
include_once 'checklist.inc';

/**
 * Represents a target present on the system being tested
 *
 * @author Ryan Prather
 */
class target
{

    /**
     * Integer used in the database for target ID
     *
     * @var integer
     */
    protected $id = 0;

    /**
     * Integer used in database for ST&E ID
     *
     * @var integer
     */
    protected $ste_id = 0;

    /**
     * Integer used in database for Category ID
     *
     * @var integer
     */
    protected $cat_id = null;

    /**
     * Integer used in database for OS ID
     *
     * @var integer
     */
    protected $os_id = 0;

    /**
     * Integer used in database for automated status ID
     *
     * @var integer
     */
    protected $auto_status_id = null;

    /**
     * Integer used in database for manual status ID
     *
     * @var integer
     */
    protected $man_status_id = null;

    /**
     * Integer used in database for data gathering status ID
     *
     * @var integer
     */
    protected $data_status_id = null;

    /**
     * Integer used in database for false positive/Cat 1 status ID
     *
     * @var integer
     */
    protected $fp_cat1_status_id = null;

    /**
     * String used to store the name of the target
     *
     * @var string
     */
    protected $name = '';

    /**
     * String to store the physical location of the target
     *
     * @var string
     */
    protected $location = '';

    /**
     * String to store the source
     *
     * @var string
     */
    protected $source = '';

    /**
     * String to store the target notes
     *
     * @var string
     */
    protected $notes = '';

    /**
     * String to store the target description
     *
     * @var string
     */
    protected $description = '';

    /**
     * String to store the target netstat connections
     *
     * @var string
     */
    protected $netstat_connections = '';

    /**
     * String to store the login on the target
     *
     * @var string
     */
    protected $login = '';

    /**
     * String to store the checklists
     *
     * @var string
     */
    protected $missing_patches = '';

    /**
     * Full OS string as detected by nessus or other tool
     *
     * @var string
     */
    protected $os_string = '';

    /**
     * Flag to post-process this host
     *
     * @var integer
     */
    protected $pp_flag = 0;

    /**
     * Flag to suspend post-processing
     *
     * @var integer
     */
    protected $pp_off = 0;

    /**
     * Array of assigned interfaces
     *
     * @var array:interface
     */
    public $interfaces = [];

    /**
     * Host classification
     *
     * @var string
     */
    public $classification = '';

    /**
     * Array of assigned checklists
     *
     * @var array:checklist
     */
    public $checklists = [];

    /**
     * Array of assigned software
     *
     * @var array:software
     */
    public $software = [];

    /**
     * List of all drives that are currently mounted by the OS (may include_once shares)
     *
     * @var string
     */
    protected $mounted = '';

    /**
     * List of all currently running processes on the target
     *
     * @var string
     */
    protected $process_list = '';

    /**
     * List of all process set to autorun with system is booted or a user logs in
     *
     * @var string
     */
    protected $autorun = '';

    /**
     * List of all services present on the target
     *
     * @var string
     */
    protected $services = '';

    /**
     * List of all local users on the target
     *
     * @var string
     */
    protected $user_list = '';

    /**
     * Time stamp of the last time the system was rebooted
     *
     * @var DateTime
     */
    protected $last_boot = null;

    /**
     * User that last logged into the system
     *
     * @var string
     */
    protected $last_login = '';

    /**
     * List of shares that are available on the target
     *
     * @var string
     */
    protected $shares = '';

    /**
     * What are the remote registry settings (Windows Only)
     *
     * @var string
     */
    protected $remote_registry = '';

    /**
     * List of users with disabled accounts
     *
     * @var string
     */
    protected $disabled_accts = '';

    /**
     * List of users that have stagnate passwords (changed >90 days ago)
     *
     * @var string
     */
    protected $stag_pwds = '';

    /**
     * List of user that have never logged into the system
     *
     * @var string
     */
    protected $never_logged_in = '';

    /**
     * List of users that have passwords set to never expire
     *
     * @var string
     */
    protected $pwd_never_expires = '';

    /**
     * Target copyright info
     *
     * @var string
     */
    protected $copyrighted = '';

    /**
     * Is this target a VM
     *
     * @var boolean
     */
    protected $is_vm = false;

    /**
     * Target system information
     *
     * @var string
     */
    protected $system = '';

    /**
     * Target bios info
     *
     * @var string
     */
    protected $bios = '';

    /**
     * Windows target pid that is WMI is listening on
     *
     * @var int
     */
    protected $wmi_listening_pid = 0;

    /**
     * Target IP routes
     *
     * @var string
     */
    protected $routes = '';

    /**
     * Target firewall configuration info
     *
     * @var string
     */
    protected $firewall_config = '';

    /**
     * Variable to store finding counts
     *
     * @var integer
     */
    protected $cat_1 = 0;

    /**
     * Variable to store finding counts
     *
     * @var integer
     */
    protected $cat_2 = 0;

    /**
     * Variable to store finding counts
     *
     * @var integer
     */
    protected $cat_3 = 0;

    /**
     * Variable to store finding counts
     *
     * @var integer
     */
    protected $nf = 0;

    /**
     * Variable to store finding counts
     *
     * @var integer
     */
    protected $nr = 0;

    /**
     * Variable to store finding counts
     *
     * @var integer
     */
    protected $na = 0;

    /**
     * Constructor
     *
     * @param string $str_Name
     */
    public function __construct($str_Name)
    {
        $this->name = $str_Name;
    }

    /**
     * Getter function for target ID
     *
     * @return integer
     */
    public function get_ID()
    {
        return $this->id;
    }

    /**
     * Setter function for target ID
     *
     * @param integer $id_in
     */
    public function set_ID($id_in)
    {
        $this->id = $id_in;
    }

    /**
     * Getter function for STE ID
     *
     * @return integer
     */
    public function get_STE_ID()
    {
        return $this->ste_id;
    }

    /**
     * Setter function for STE ID
     *
     * @param integer $int_STE_ID
     */
    public function set_STE_ID($int_STE_ID)
    {
        $this->ste_id = $int_STE_ID;
    }

    /**
     * Getter function for category ID
     *
     * @return integer
     */
    public function get_Cat_ID()
    {
        return $this->cat_id;
    }

    /**
     * Setter function for category Id
     *
     * @param integer $int_Cat_ID
     */
    public function set_Cat_ID($int_Cat_ID)
    {
        $this->cat_id = $int_Cat_ID;
    }

    /**
     * Getter function for the OS ID
     *
     * @return integer
     */
    public function get_OS_ID()
    {
        return $this->os_id;
    }

    /**
     * Setter function for OS ID
     *
     * @param integer $int_OS_ID
     */
    public function set_OS_ID($int_OS_ID)
    {
        $this->os_id = $int_OS_ID;
    }

    /**
     * Getter function for automated scan status
     *
     * @return integer
     */
    public function get_Auto_Status_ID()
    {
        return $this->auto_status_id;
    }

    /**
     * Setter function for automated scan status
     *
     * @param integer $int_Auto_Status_ID
     */
    public function set_Auto_Status_ID($int_Auto_Status_ID)
    {
        $this->auto_status_id = $int_Auto_Status_ID;
    }

    /**
     * Getter function for manual scan status
     *
     * @return integer
     */
    public function get_Man_Status_ID()
    {
        return $this->man_status_id;
    }

    /**
     * Setter function for manual scan status
     *
     * @param integer $int_Man_Status_ID
     */
    public function set_Man_Status_ID($int_Man_Status_ID)
    {
        $this->man_status_id = $int_Man_Status_ID;
    }

    /**
     * Getter function for data gathering scan status
     *
     * @return integer
     */
    public function get_Data_Status_ID()
    {
        return $this->data_status_id;
    }

    /**
     * Setter function for data gathering scan status
     *
     * @param integer $int_Data_Status_ID
     */
    public function set_Data_Status_ID($int_Data_Status_ID)
    {
        $this->data_status_id = $int_Data_Status_ID;
    }

    /**
     * Getter function for FP Cat1 scan status
     *
     * @return integer
     */
    public function get_FP_Cat1_Status_ID()
    {
        return $this->fp_cat1_status_id;
    }

    /**
     * Setter function for FP/Cat1 scan status
     *
     * @param integer $int_FP_Cat1_Status_ID
     */
    public function set_FP_Cat1_Status_ID($int_FP_Cat1_Status_ID)
    {
        $this->fp_cat1_status_id = $int_FP_Cat1_Status_ID;
    }

    /**
     * Getter function for target name
     *
     * @return string
     */
    public function get_Name()
    {
        return $this->name;
    }

    /**
     * Setter function for target name
     *
     * @param string $str_Name
     */
    public function set_Name($str_Name)
    {
        $this->name = $str_Name;
    }

    /**
     * Getter function for target location
     *
     * @return string
     */
    public function get_Location()
    {
        return $this->location;
    }

    /**
     * Setter function for target location
     *
     * @param string $str_Location
     */
    public function set_Location($str_Location)
    {
        $this->location = $str_Location;
    }

    /**
     * Gettr function for target source
     *
     * @return string
     */
    public function get_Source()
    {
        return $this->source;
    }

    /**
     * Setter function for target source
     *
     * @param string $str_Source
     */
    public function set_Source($str_Source)
    {
        $this->source = $str_Source;
    }

    /**
     * Getter function for target notes
     *
     * @return string
     */
    public function get_Notes()
    {
        return $this->notes;
    }

    /**
     * Function to get the formatted notes for display
     *
     * @return string
     */
    public function getDisplayNotes()
    {
        $notes = explode("\n", $this->notes);
        $note  = null;
        if (is_array($notes) && isset($notes[0]) && strlen($notes[0]) <= 125) {
            $note = $notes[0];
        }
        elseif (is_array($notes) && isset($notes[0]) && strlen($notes[0]) > 125) {
            $note = substr($notes[0], 0, 125);
        }

        if (is_array($notes) && count($notes) > 1) {
            unset($notes[0]);
            $extra_notes = implode("\n", $notes);
            if (strlen($extra_notes)) {
                $note .= "&nbsp;<i class='fas fa-ellipsis-h' title='{$extra_notes}'></i>";
            }
        }

        return $note;
    }

    /**
     * Setter function for target notes
     *
     * @param string $str_Notes
     */
    public function set_Notes($str_Notes)
    {
        $this->notes = $str_Notes;
    }

    /**
     * Function to append notes
     *
     * @param string $str_Notes
     */
    public function append_Notes($str_Notes)
    {
        $this->notes .= $str_Notes;
    }

    /**
     * Getter function for target netstat connections
     *
     * @return string
     */
    public function get_Netstat_Connections()
    {
        return $this->netstat_connections;
    }

    /**
     * Setter function for target netstat connections
     *
     * @param string $str_Netstat_Connections
     */
    public function set_Netstat_Connections($str_Netstat_Connections)
    {
        $this->netstat_connections = $str_Netstat_Connections;
    }

    /**
     * Function to append a connection to the netstat string
     *
     * @param string $str_Netstat_Connections
     */
    public function append_Connection($str_Netstat_Connections)
    {
        $this->netstat_connections .= $str_Netstat_Connections;
    }

    /**
     * Getter function for login
     *
     * @return string
     */
    public function get_Login()
    {
        return $this->login;
    }

    /**
     * Setter funciton for login
     *
     * @param string $str_Login
     */
    public function set_Login($str_Login)
    {
        $this->login = $str_Login;
    }

    /**
     * Getter function for missing patches
     *
     * @return string
     */
    public function get_Missing_Patches()
    {
        return $this->missing_patches;
    }

    /**
     * Setter function for missing patches
     *
     * @param string $str_Missing_Patches
     */
    public function set_Missing_Patches($str_Missing_Patches)
    {
        $this->missing_patches = $str_Missing_Patches;
    }

    /**
     * Returns the OS string of the target
     *
     * @return string
     */
    public function get_OS_String()
    {
        return $this->os_string;
    }

    /**
     * Set OS String
     *
     * @param string $os_string
     */
    public function set_OS_String($os_string)
    {
        $this->os_string = $os_string;
    }

    /**
     * Returns true if system needs to be post-processed
     *
     * @return boolean
     */
    public function is_PP_Flag_Set()
    {
        return $this->pp_flag;
    }

    /**
     * Sets the post-processing flag
     *
     * @param boolean $pp_flag
     */
    public function set_PP_Flag($pp_flag)
    {
        $this->pp_flag = $pp_flag;
    }

    /**
     * Returns true if post-processing is suspended
     *
     * @return boolean
     */
    public function is_PP_Suspended()
    {
        return $this->pp_off;
    }

    /**
     * Suspends the post-processing
     *
     * @param boolean $pp_off
     */
    public function set_PP_Suspended($pp_off)
    {
        $this->pp_off = $pp_off;
    }

    /**
     * Getter function for mounted info
     *
     * @return string
     */
    public function get_Mounted()
    {
        return $this->mounted;
    }

    /**
     * Setter function for mounted info
     *
     * @param string $str_Mounted
     */
    public function set_Mounted($str_Mounted)
    {
        $this->mounted = $str_Mounted;
    }

    /**
     * Getter function for process list
     *
     * @return string
     */
    public function get_Process_List()
    {
        return $this->process_list;
    }

    /**
     * Setter function for process list
     *
     * @param string $str_Process_List
     */
    public function set_Process_List($str_Process_List)
    {
        $this->process_list = $str_Process_List;
    }

    /**
     * Getter function for autorun list
     *
     * @return string
     */
    public function get_Autorun()
    {
        return $this->autorun;
    }

    /**
     * Setter function for autorun list
     *
     * @param string $str_Autorun
     */
    public function set_Autorun($str_Autorun)
    {
        $this->autorun = $str_Autorun;
    }

    /**
     * Getter function target service list
     *
     * @return string
     */
    public function get_Services()
    {
        return $this->services;
    }

    /**
     * Setter function for target service list
     *
     * @param string $str_Services
     */
    public function set_Services($str_Services)
    {
        $this->services = $str_Services;
    }

    /**
     * Getter function for target user list
     *
     * @return string
     */
    public function get_User_List()
    {
        return $this->user_list;
    }

    /**
     * Setter function for target user list
     *
     * @param string $str_User_List
     */
    public function set_User_List($str_User_List)
    {
        $this->user_list = $str_User_List;
    }

    /**
     * Getter function for last boot datetime stamp
     *
     * @return DateTime
     */
    public function get_Last_Boot()
    {
        return $this->last_boot;
    }

    /**
     * Setter function for last boot timestamp
     *
     * @param string|DateTime $str_Last_Boot
     */
    public function set_Last_Boot($str_Last_Boot)
    {
        if (is_a($str_Last_Boot, 'DateTime')) {
            $this->last_boot = $str_Last_Boot;
        }
        else {
            $this->last_boot = new DateTime($str_Last_Boot);
        }
    }

    /**
     * Getter function for last logged in user
     *
     * @return string
     */
    public function get_Last_Login()
    {
        return $this->last_login;
    }

    /**
     * Setter function for last logged in user
     *
     * @param string $str_Last_Login
     */
    public function set_Last_Login($str_Last_Login)
    {
        $this->last_login = $str_Last_Login;
    }

    /**
     * Getter function for target shares
     *
     * @return string
     */
    public function get_Shares()
    {
        return $this->shares;
    }

    /**
     * Setter function for target shares
     *
     * @param string $str_Shares
     */
    public function set_Shares($str_Shares)
    {
        $this->shares = $str_Shares;
    }

    /**
     * Getter function for remote registry settings
     *
     * @return string
     */
    public function get_Remote_Registry()
    {
        return $this->remote_registry;
    }

    /**
     * Setter function for remote registry settings
     *
     * @param string $str_Remote_Registry
     */
    public function set_Remote_Registry($str_Remote_Registry)
    {
        $this->remote_registry = $str_Remote_Registry;
    }

    /**
     * Getter function for disabled user accounts
     *
     * @return string
     */
    public function get_Disabled_Accts()
    {
        return $this->disabled_accts;
    }

    /**
     * Setter function for disabled user accounts
     *
     * @param string $str_Disabled_Accts
     */
    public function set_Disabled_Accts($str_Disabled_Accts)
    {
        $this->disabled_accts = $str_Disabled_Accts;
    }

    /**
     * Getter function for stagnant user passwords
     *
     * @return string
     */
    public function get_Stag_Pwds()
    {
        return $this->stag_pwds;
    }

    /**
     * Setter function for stagnant user passwords
     *
     * @param string $str_Stag_Pwds
     */
    public function set_Stag_Pwds($str_Stag_Pwds)
    {
        $this->stag_pwds = $str_Stag_Pwds;
    }

    /**
     * Getter function for user never logged in
     *
     * @return string
     */
    public function get_Never_Logged_In()
    {
        return $this->never_logged_in;
    }

    /**
     * Setter function for users never logged in
     *
     * @param string $str_Never_Logged_In
     */
    public function set_Never_Logged_In($str_Never_Logged_In)
    {
        $this->never_logged_in = $str_Never_Logged_In;
    }

    /**
     * Getter function for passwords that never expire
     *
     * @return string
     */
    public function get_Pwds_Never_Expire()
    {
        return $this->pwd_never_expires;
    }

    /**
     * Setter function for passwords that never expire
     *
     * @param string $str_Pwd_Never_Expire
     */
    public function set_Pwds_Never_Expire($str_Pwd_Never_Expire)
    {
        $this->pwd_never_expires = $str_Pwd_Never_Expire;
    }

    /**
     * Getter function for copyright info
     *
     * @return string
     */
    public function get_Copyright()
    {
        return $this->copyrighted;
    }

    /**
     * Setter function for copyright info
     *
     * @param string $str_Copyright
     */
    public function set_Copyright($str_Copyright)
    {
        $this->copyrighted = $str_Copyright;
    }

    /**
     * Is the target a virtual machine guest
     *
     * @return boolean
     */
    public function is_VM()
    {
        return $this->is_vm;
    }

    /**
     * Set if the target is a virtual machine guest
     *
     * @param string $is_VM
     */
    public function set_VM($is_VM)
    {
        $this->is_vm = $is_VM;
    }

    /**
     * Getter function for system information
     *
     * @return string
     */
    public function get_System()
    {
        return $this->system;
    }

    /**
     * Setter function for system information
     *
     * @param string $str_System
     */
    public function set_System($str_System)
    {
        $this->system = $str_System;
    }

    /**
     * Getter function for system BIOS information
     *
     * @return string
     */
    public function get_BIOS()
    {
        return $this->bios;
    }

    /**
     * Setter function for system BIOS informatino
     *
     * @param string $str_BIOS
     */
    public function set_BIOS($str_BIOS)
    {
        $this->bios = $str_BIOS;
    }

    /**
     * Getter function for the PID that WMI is running on
     *
     * @return int
     */
    public function get_WMI_PID()
    {
        return $this->wmi_listening_pid;
    }

    /**
     * Setter function for PID that WMI is running on
     *
     * @param int $int_WMI_PID
     */
    public function set_WMI_PID($int_WMI_PID)
    {
        $this->wmi_listening_pid = $int_WMI_PID;
    }

    /**
     * Getter function for target routing information
     *
     * @return string
     */
    public function get_Routes()
    {
        return $this->routes;
    }

    /**
     * Setter function for targert routing information
     *
     * @param string $str_Routes
     */
    public function set_Routes($str_Routes)
    {
        $this->routes = $str_Routes;
    }

    /**
     * Getter function for the target firewall configuration
     *
     * @return string
     */
    public function get_Firewall_Config()
    {
        return $this->firewall_config;
    }

    /**
     * Setter function for the target firewall configuration
     *
     * @param string $str_Firewall_Config
     */
    public function set_Firewall_Config($str_Firewall_Config)
    {
        $this->firewall_config = $str_Firewall_Config;
    }

    /**
     * Getter function for cat_1 findings
     *
     * @return integer
     */
    public function getCat1Count()
    {
        return $this->cat_1;
    }

    /**
     * Setter function for cat_1 findings
     *
     * @param integer $count
     */
    public function setCat1Count($count)
    {
        if (is_numeric($count) && $count > 0) {
            $this->cat_1 = $count;
        }
    }

    /**
     * Getter function for cat_2 finding
     *
     * @return integer
     */
    public function getCat2Count()
    {
        return $this->cat_2;
    }

    /**
     * Setter function for cat_2 findings
     *
     * @param integer $count
     */
    public function setCat2Count($count)
    {
        if (is_numeric($count) && $count > 0) {
            $this->cat_2 = $count;
        }
    }

    /**
     * Getter function for cat_3 findings
     *
     * @return integer
     */
    public function getCat3Count()
    {
        return $this->cat_3;
    }

    /**
     * Setter function for cat_3 findings
     *
     * @param integer $count
     */
    public function setCat3Count($count)
    {
        if (is_numeric($count) && $count > 0) {
            $this->cat_3 = $count;
        }
    }

    /**
     * Getter function for nf findings
     *
     * @return integer
     */
    public function getNotAFindingCount()
    {
        return $this->nf;
    }

    /**
     * Setter function for nf findings
     *
     * @param integer $count
     */
    public function setNotAFindingCount($count)
    {
        if (is_numeric($count) && $count > 0) {
            $this->nf = $count;
        }
    }

    /**
     * Getter function for na findings
     *
     * @return integer
     */
    public function getNotApplicableCount()
    {
        return $this->na;
    }

    /**
     * Setter function for na findings
     *
     * @param integer $count
     */
    public function setNotApplicableCount($count)
    {
        if (is_numeric($count) && $count > 0) {
            $this->na = $count;
        }
    }

    /**
     * Getter function for nr findings
     *
     * @return integer
     */
    public function getNotReviewedCount()
    {
        return $this->nr;
    }

    /**
     * Setter function for nr findings
     *
     * @param integer $count
     */
    public function setNotReviewedCount($count)
    {
        if (is_numeric($count) && $count > 0) {
            $this->nr = $count;
        }
    }

    /**
     * Getter method to calculate the total finding count
     *
     * @return integer
     */
    public function getTotalFindingCount()
    {
        return ($this->nr +
            $this->na +
            $this->nf +
            $this->cat_1 +
            $this->cat_2 +
            $this->cat_3);
    }

    /**
     * Getter method to calculate the compliant percentage
     *
     * @return float
     */
    public function getCompliantPercent()
    {
        if ($this->getTotalFindingCount() - $this->nr == 0) {
            return 0;
        }
        $comp = ($this->na + $this->nf) / ($this->getTotalFindingCount() - $this->nr);
        return $comp;
    }

    /**
     * Getter method to calculate the assessed percentage
     *
     * @return float
     */
    public function getAssessedPercent()
    {
        if ($this->getTotalFindingCount() == 0) {
            return 0;
        }
        $ass  = ($this->getTotalFindingCount() - $this->nr) / $this->getTotalFindingCount();
        return $ass;
    }

    /**
     * Returns the first non-loopback, non-0 IP address for the target or NULL if none found.
     *
     * @return string|NULL
     */
    public function getIP()
    {
        foreach($this->interfaces as $int) {
            if(!in_array($int->get_IPv4(), ['0.0.0.0', '127.0.0.1', ''])) {
                return $int->get_IPv4();
            }
        }
        return null;
    }

    /**
     * Getter function for pre-formatted table row
     *
     * @param boolean $odd
     *
     * @return string
     */
    public function get_Table_Row($odd)
    {
        if ($odd) {
            $class = "odd_row";
        }
        else {
            $class = "even_row";
        }

        $auto_class = "task-" . str_replace(' ', '_', strtolower($this->get_Task_Status($this->auto_status_id)));
        $man_class  = "task-" . str_replace(' ', '_', strtolower($this->get_Task_Status($this->man_status_id)));
        $data_class = "task-" . str_replace(' ', '_', strtolower($this->get_Task_Status($this->data_status_id)));
        $fp_class   = "task-" . str_replace(' ', '_', strtolower($this->get_Task_Status($this->fp_cat1_status_id)));

        $ret = "<tr class='$class cat_" . $this->cat_id . "'>" .
            "<td style='width:110px;'>" .
            "<input type='checkbox' value='" . $this->id . "' onclick='javascript:update_tgt_chk(this);' />" .
            "<a href='target.php?ste=" . $this->ste_id . "&tgt=" . $this->id . "' class='host'>" . $this->name . "</a>";

        foreach ($this->interfaces as $int) {
            if (false) {
                $int = new interfaces();
            }
            if (!in_array($int->get_IPv4(), array("127.0.0.1", "0.0.0.0"))) {
                $ret .= "<a href='target.php?ste=" . $this->ste_id . "&tgt=" . $this->id . "' class='ip'>" . $int->get_IPv4() . "</a>";
                break;
            }
        }

        $ret .= "</td>" .
            "<td style='width:100px;line-height:1.25;'>" . $this->os_string . "</td>" .
            "<td style='width:100px;'>" . $this->location . "</td>" .
            "<td class='$auto_class'>" . $this->get_Task_Status($this->auto_status_id) . "</td>" .
            "<td class='$man_class'>" . $this->get_Task_Status($this->man_status_id) . "</td>" .
            "<td class='$data_class'>" . $this->get_Task_Status($this->data_status_id) . "</td>" .
            "<td class='$fp_class'>" . $this->get_Task_Status($this->fp_cat1_status_id) . "</td>" .
            "<td>";

        $icons = array();

        if (is_array($this->checklists) && count($this->checklists)) {
            foreach ($this->checklists as $key => $chklst) {
                $current_icon = $chklst->get_Icon();
                if ($current_icon == '') {
                    continue;
                }

                if (!array_key_exists($current_icon, $icons)) {
                    $icons[$current_icon] = array(
                        'icon'  => $current_icon,
                        'title' => '- ' . $chklst->get_Name() . " V" . $chklst->get_Version() . "R" . $chklst->get_Release() . ' (' . $chklst->get_type() . ')'
                    );
                }
                else {
                    $icons[$current_icon]['title'] .= PHP_EOL . " - " . $chklst->get_Name() . " V" . $chklst->get_Version() . "R" . $chklst->get_Release() . ' (' .
                        $chklst->get_type() . ')';
                }
            }
        }

        if (is_array($icons) && count($icons)) {
            foreach ($icons as $key => $icon) {
                $ret .= "<img src='/img/checklist_icons/" . $icon['icon'] . "' title='" . $icon['title'] .
                    "' class='checklist_image' />";
            }
        }
        else {
            $ret .= "&nbsp;";
        }


        $ret .= "</td>" . "<td style='width:350px;'>" . $this->notes . "</td>" . "</tr>";

        return $ret;
    }

    /**
     * Getter function for task status
     *
     * @param integer $intStatus
     * @return string
     */
    public function get_Task_Status($intStatus)
    {
        $status = array(
            1 => "Comp",
            2 => "IP",
            3 => "NP",
            4 => "NA",
            5 => "NR"
        );

        if (is_numeric($intStatus)) {
            return $status[$intStatus];
        }
        else {
            return 'NR';
        }
    }

    /**
     * Get array to convert to JSON
     *
     * @return array
     */
    public function get_JSON()
    {
        return array(
            'id'       => $this->id,
            'ste_id'   => $this->ste_id,
            'cat_id'   => $this->cat_id,
            'name'     => $this->name,
            'os'       => $this->os_string,
            'location' => $this->location,
            'notes'    => nl2br($this->notes)
        );
    }
}
