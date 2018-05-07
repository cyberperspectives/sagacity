<?php
/**
 * File: checklist.inc
 * Author: Ryan Prather
 * Purpose: Represents a checklist that links a PDI and software package
 * Created: Sep 12, 2013
 *
 * Portions Copyright 2017: Cyber Perspectives, All rights reserved
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
 *  - Mar 3, 2017 - Added method to find icon based on checklist name and cleaned up print_Option method
 *  - Mar 4, 2017 - Fixed type with Windows icon image (used .jpg instead of .png)
 *  - May 13, 2017 - Added WindowsFirewall.jpg image for checklist
 *  - May 19, 2017 - Fixed typo for WindowsFirewall
 *  - Aug 23, 2017 - JO, Expanded checklist icons
 */

/**
 * Represents a checklist that links a PDI and software package
 *
 * @author Ryan Prather
 *
 */
class checklist
{

    /**
     * The ID of the checklist
     *
     * @var integer
     */
    public $id = 0;

    /**
     * The checklist ID
     *
     * @var string
     */
    public $checklist_id = '';

    /**
     * Array of software that this checklist is applicable on
     *
     * @var array
     */
    public $sw = null;

    /**
     * The name of the checklist
     *
     * @var string
     */
    public $name = '';

    /**
     * The checklist description
     *
     * @var string
     */
    public $description = '';

    /**
     * The date of release
     *
     * @var DateTime
     */
    public $date;

    /**
     * The file name that contains the checklist
     *
     * @var string
     */
    public $file_name = '';

    /**
     * The checklist version
     *
     * @var integer
     */
    public $ver = 0;

    /**
     * The checklist release
     *
     * @var string
     */
    public $release = 0;

    /**
     * The checklist type (benchmark, manual)
     *
     * @var string
     */
    public $type = '';

    /**
     * The file name of the icon to display
     *
     * @var string
     */
    public $icon = '';

    /**
     * Classification of the checklist
     *
     * @var string
     */
    public $classification = '';

    /**
     * Constructor
     *
     * @param integer $int_ID
     * @param string $str_Checklist_ID
     * @param string $str_Name
     * @param string $str_Description
     * @param DateTime $dt_Date
     * @param string $str_File_Name
     * @param integer $int_Ver
     * @param string $str_Release
     * @param string $str_Type
     * @param string $str_Icon
     */
    public function __construct($int_ID, $str_Checklist_ID, $str_Name, $str_Description, $dt_Date, $str_File_Name, $int_Ver, $str_Release, $str_Type, $str_Icon)
    {
        $this->id           = $int_ID;
        $this->checklist_id = $str_Checklist_ID;
        $this->name         = str_ireplace("STIG STIG", "STIG", str_ireplace("Secure Technical Implementation Guide", "STIG", $str_Name));
        $this->description  = $str_Description;
        if (is_string($dt_Date)) {
            $this->date = new DateTime($dt_Date);
        }
        else {
            $this->date = $dt_Date;
        }
        $this->file_name = $str_File_Name;
        $this->ver       = $int_Ver;
        $this->release   = $str_Release;
        $this->type      = $str_Type;

        if (!$str_Icon) {
            $this->find_Icon();
        }
        else {
            $this->icon = $str_Icon;
        }

        $this->sw = array();
    }

    /**
     * Getter function for the ID
     *
     * @return integer
     */
    public function get_ID()
    {
        return $this->id;
    }

    /**
     * Getter function for the checklist ID
     *
     * @return string
     */
    public function get_Checklist_ID()
    {
        return $this->checklist_id;
    }

    /**
     * Getter function for the software ID
     *
     * @return integer
     */
    public function get_SW()
    {
        return $this->sw;
    }

    /**
     * Function to add a software object to the applicable software array
     *
     * @param software $sw_in
     */
    public function add_SW($sw_in)
    {
        if (is_a($sw_in, "software")) {
            $this->sw[$sw_in->get_ID()] = $sw_in;
        }
        elseif (is_array($sw_in)) {
            $this->sw = array_merge($this->sw, $sw_in);
        }
    }

    /**
     * Getter function for the checklist name
     *
     * @return string
     */
    public function get_Name()
    {
        return $this->name;
    }

    /**
     * Gettr function for the checklist description
     *
     * @return string
     */
    public function get_Description()
    {
        return $this->description;
    }

    /**
     * Getter function for the release date
     *
     * @return DateTime
     */
    public function get_Date()
    {
        return $this->date;
    }

    /**
     * Getter function for the file name
     *
     * @return string
     */
    public function get_File_Name()
    {
        return $this->file_name;
    }

    /**
     * Getter function for the checklist version
     *
     * @return integer
     */
    public function get_Version()
    {
        return $this->ver;
    }

    /**
     * Getter function for the checklist release
     *
     * @return string
     */
    public function get_Release()
    {
        return $this->release;
    }

    /**
     * Getter function for the checklist type
     *
     * @return string
     */
    public function get_type()
    {
        return $this->type;
    }

    /**
     * Getter function for the checklist icon
     *
     * @return string
     */
    public function get_Icon()
    {
        return $this->icon;
    }

    /**
     * Getter function for the checklist classification
     *
     * @return string
     */
    public function get_Classification()
    {
        return $this->classification;
    }

    /**
     * Setter function for the checklist classification
     *
     * @param string $class_in
     */
    public function set_Classification($class_in)
    {
        $this->classification = $class_in;
    }

    /**
     * Function to determine the Checklist icon based on the name
     */
    public function find_Icon()
    {
        if (!empty($this->name)) {
            switch ($this->name) {
                case (preg_match("/AIX/i", $this->name) ? true : false):
                    $this->icon = 'AIX.png';
                    break;
                case (preg_match("/Application Security|Application Server|Application Layer Gateway/i", $this->name) ? true : false):
                    $this->icon = 'Application Development.gif';
                    break;
                case (preg_match("/Active Directory/i", $this->name) ? true : false):
                    $this->icon = 'Active Directory.png';
                    break;
                case (preg_match("/Acrobat Reader|Adobe Acrobat/i", $this->name) ? true : false):
                    $this->icon = 'Adobe Reader.png';
                    break;
                case (preg_match("/Coldfusion/i", $this->name) ? true : false):
                    $this->icon = 'Adobe Coldfusion.png';
                    break;
                case (preg_match("/Apache/i", $this->name) ? true : false):
                    $this->icon = 'Apache Web.jpg';
                    break;
                case (preg_match("/Apple OS X|Apple iOS/i", $this->name) ? true : false):
                    $this->icon = 'Apple.jpg';
                    break;
                case (preg_match("/Blackberry|BB10|BBDS10/i", $this->name) ? true : false):
                    $this->icon = 'Blackberry.jpg';
                    break;
                case (preg_match("/DNS/i", $this->name) ? true : false):
                    $this->icon = 'DNS.jpg';
                    break;
                case (preg_match("/ESXi/i", $this->name) ? true : false):
                    $this->icon = 'VMware (ESXi).jpg';
                    break;
                case (preg_match("/VMWare/i", $this->name) ? true : false);
                    $this->icon = 'VMware.jpg';
                    break;
                case (preg_match("/Exchange/i", $this->name) ? true : false):
                    $this->icon = 'Microsoft Exchange.gif';
                    break;
                case (preg_match("/Google Chrome/i", $this->name) ? true : false):
                    $this->icon = 'Google Chrome.jpg';
                    break;
                case (preg_match("/HP\-UX/i", $this->name) ? true : false):
                    $this->icon = 'HPUX.jpg';
                    break;
                case (preg_match("/IIS/i", $this->name) ? true : false):
                    $this->icon = 'Microsoft IIS.png';
                    break;
                case (preg_match("/Intrusion Detection/i", $this->name) ? true : false):
                    $this->icon = 'Intrusion Detection System.jpg';
                    break;
                case (preg_match("/Keyboard Video/i", $this->name) ? true : false):
                    $this->icon = 'KVM.jpg';
                    break;
                case (preg_match("/Android/i", $this->name) ? true : false):
                    $this->icon = 'Android.gif';
                    break;
                case (preg_match("/MS SQL|Microsoft SQL Server/i", $this->name) ? true : false):
                    $this->icon = 'MSSQL.png';
                    break;
                case (preg_match("/Oracle Database/i", $this->name) ? true : false):
                    $this->icon = 'Oracle Database.png';
                    break;
                case (preg_match("/Database|Postgres/i", $this->name) ? true : false):
                    $this->icon = 'Database.png';
                    break;
                case (preg_match("/Java Runtime|JRE/i", $this->name) ? true : false):
                    $this->icon = 'Sun Java.jpg';
                    break;
                case (preg_match("/Windows Firewall/i", $this->name) ? true : false):
                    $this->icon = 'WindowsFirewall.jpg';
                    break;
                case (preg_match("/Windows Server \d{4}|Windows \d{4}/i", $this->name) ? true : false):
                    $this->icon = "WindowsServer.png";
                    break;
                case (preg_match("/Windows ([\d]+|Vista|XP)/i", $this->name) ? true : false):
                    $this->icon = "Windows.png";
                    break;
                case (preg_match("/Windows Defender/i", $this->name) ? true : false):
                    $this->icon = "Windows Defender.png";
                    break;
                case (preg_match("/Web Server|Oracle HTTP|Oracle WebLogic/i", $this->name) ? true : false):
                    $this->icon = 'Web Server.png';
                    break;
                case (preg_match("/Mcafee/i", $this->name) ? true : false):
                    $this->icon = 'Mcafee.jpg';
                    break;
                case (preg_match("/Microsoft (Access|Excel|PowerPoint|Groove|InfoPath|Lync|Office System|OneNote|Outlook|Project|Publisher|Visio|Word) ([\d]+)/i", $this->name) ? true : false):
                    $this->icon = "Office.png";
                    break;
                case (preg_match("/SharePoint/i", $this->name) ? true : false):
                    $this->icon = 'Microsoft Sharepoint.png';
                    break;
                case (preg_match("/Dot Net/i", $this->name) ? true : false):
                    $this->icon = 'Microsoft .NET.png';
                    break;
                case (preg_match("/Internet Explorer/i", $this->name) ? true : false):
                    $this->icon = 'Internet Explorer.png';
                    break;
                case (preg_match("/Windows Phone/i", $this->name) ? true : false):
                    $this->icon = 'Windows Phone.jpg';
                    break;
                case (preg_match("/Mozilla Firefox/i", $this->name) ? true : false):
                    $this->icon = 'Firefox.png';
                    break;
                case (preg_match("/Network Printers/i", $this->name) ? true : false):
                    $this->icon = 'Printer Scanner Fax.jpg';
                    break;
                case (preg_match("/Firewall[^C]+Cisco/i", $this->name) ? true : false):
                case (preg_match("/Firewall/i", $this->name) ? true : false):
                    $this->icon = 'Firewall.jpg';
                    break;
                case (preg_match("/VPN/i", $this->name) ? true : false):
                    $this->icon = 'VPN.jpg';
                    break;
                case (preg_match("/Switch([^C]+)Cisco/i", $this->name) ? true : false):
                    $this->icon = 'Cisco Switch.jpg';
                    break;
                case (preg_match("/Switch/i", $this->name) ? true : false):
                    $this->icon = 'Network Switch.png';
                    break;
                case (preg_match("/Router[^C]+Cisco/i", $this->name) ? true : false):
                    $this->icon = 'Cisco Router.jpg';
                    break;
                case (preg_match("/Router/i", $this->name) ? true : false):
                    $this->icon = 'Network Router.png';
                    break;
                case (preg_match("/WLAN|WMAN/i", $this->name) ? true : false):
                    $this->icon = 'Network Device.jpg';
                    break;
                case (preg_match("/Network/i", $this->name) ? true : false):
                    $this->icon = 'Network Device.jpg';
                    break;
                case (preg_match("/Skype/i", $this->name) ? true : false):
                    $this->icon = 'Skype.png';
                    break;
                case (preg_match("/OneDrive/i", $this->name) ? true : false):
                    $this->icon = 'OneDrive.png';
                    break;
                case (preg_match("/Red ?Hat/i", $this->name) ? true : false):
                    $this->icon = 'RedHat Linux.jpg';
                    break;
                case (preg_match("/SUSE Linux/i", $this->name) ? true : false):
                    $this->icon = 'SUSE Linux.png';
                    break;
                case (preg_match("/Solaris/i", $this->name) ? true : false):
                    $this->icon = 'Solaris Unix.png';
                    break;
                case (preg_match("/Storage Area/i", $this->name) ? true : false):
                    $this->icon = 'Storage Area Network.gif';
                    break;
                case (preg_match("/z\/OS/i", $this->name) ? true : false):
                    $this->icon = 'ZOS.jpg';
                    break;
                // Added by Jeff Odegard, 23 Aug 17
                case (preg_match("/Email Services Policy/i", $this->name) ? true : false):
                    $this->icon = 'exchange.png';
                    break;
                case (preg_match("/L3/i", $this->name) ? true : false):
                    $this->icon = 'L3.png';
                    break;
                case (preg_match("/Symantec/i", $this->name) ? true : false):
                    $this->icon = 'Symantec.jpg';
                    break;
                case (preg_match("/Tanium/i", $this->name) ? true : false):
                    $this->icon = 'Tanium.jpeg';
                    break;
                case (preg_match("/Voice Video Services/i", $this->name) ? true : false):
                    $this->icon = 'voip.jpg';
                    break;
                case (preg_match("/Video Services|VTC/i", $this->name) ? true : false):
                    $this->icon = 'video-conferencing.png';
                    break;
                case (preg_match("/Voice Video/i", $this->name) ? true : false):
                    $this->icon = 'voice-video.png';
                    break;
                case (preg_match("/Sun Ray/i", $this->name) ? true : false):
                    $this->icon = 'sunray.jpg';
                    break;
                case (preg_match("/VOIP/i", $this->name) ? true : false):
                    $this->icon = 'voip.jpg';
                    break;
                case (preg_match("/SteelHead/i", $this->name) ? true : false):
                    $this->icon = 'SteelHead.png';
                    break;
                case (preg_match("/SmartPhone/i", $this->name) ? true : false):
                    $this->icon = 'mobile.jpg';
                    break;
                case (preg_match("/MAC OSX/i", $this->name) ? true : false):
                    $this->icon = 'mac-os-x.png';
                    break;
                case (preg_match("/Good/i", $this->name) ? true : false):
                    $this->icon = 'good.png';
                    break;
                case (preg_match("/Oracle Linux/i", $this->name) ? true : false):
                    $this->icon = 'oracle-linux.png';
                    break;
                case (preg_match("/Juniper/i", $this->name) ? true : false):
                    $this->icon = 'juniper-networks.png';
                    break;
                case (preg_match("/Jboss/i", $this->name) ? true : false):
                    $this->icon = 'jboss.png';
                    break;
                case (preg_match("/Google/i", $this->name) ? true : false):
                    $this->icon = 'Google-Search-Appliance.jpg';
                    break;
                case (preg_match("/Wireless/i", $this->name) ? true : false):
                    $this->icon = 'wireless.png';
                    break;
                case (preg_match("/F5 BIG/i", $this->name) ? true : false):
                    $this->icon = 'f5-big-ip.jpg';
                    break;
                case (preg_match("/Test and Development Zone/i", $this->name) ? true : false):
                    $this->icon = 'Enclave.jpg';
                    break;
                case (preg_match("/Arista/i", $this->name) ? true : false):
                    $this->icon = 'Arista.png';
                    break;
                case (preg_match("/CA API/i", $this->name) ? true : false):
                    $this->icon = 'CA TEchnologies.jpg';
                    break;
                case (preg_match("/Cisco IOS/i", $this->name) ? true : false):
                    $this->icon = 'Cisco IOS.jpg';
                    break;
                case (preg_match("/BIND 9/i", $this->name) ? true : false):
                    $this->icon = 'BIND DNS.jpg';
                    break;
                case (preg_match("/MobileIron/i", $this->name) ? true : false):
                    $this->icon = 'mobileiron.png';
                    break;
                case (preg_match("/Mobile Policy/i", $this->name) ? true : false):
                    $this->icon = 'mobile.jpg';
                    break;
                case (preg_match("/Mobile Device/i", $this->name) ? true : false):
                    $this->icon = 'mobile-device.jpg';
                    break;
                case (preg_match("/BIND 9/i", $this->name) ? true : false):
                    $this->icon = 'BIND DNS.jpg';
                    break;
                case (preg_match("/Remote Access/i", $this->name) ? true : false):
                    $this->icon = 'remote-access.gif';
                    break;
                case (preg_match("/Remote Endpoint/i", $this->name) ? true : false):
                    $this->icon = 'Remote-Endpoint.jpg';
                    break;
                case (preg_match("/Xenapp/i", $this->name) ? true : false):
                    $this->icon = 'xenapp.jpg';
                    break;
                case (preg_match("/Removable Storage/i", $this->name) ? true : false):
                    $this->icon = 'storage.jpg';
                    break;
                case (preg_match("/Traditional Security/i", $this->name) ? true : false):
                    $this->icon = 'security.jpg';
                    break;
                case (preg_match("/IBM/i", $this->name) ? true : false):
                    $this->icon = 'IBM.jpg';
                    break;
                case (preg_match("/Operating System/i", $this->name) ? true : false):
                    $this->icon = 'operating_system.png';
                    break;
                case (preg_match("/HPE 3PAR/i", $this->name) ? true : false):
                    $this->icon = 'HP-3par-logo.jpg';
                    break;
                case (preg_match("/MDM /i", $this->name) ? true : false):
                    $this->icon = 'mobile-device-management.png';
                    break;
                case (preg_match("/Mainframe /i", $this->name) ? true : false):
                    $this->icon = 'mainframe.png';
                    break;
                default:
                    $this->icon = 'Orphan.png';
            }
        }
    }

    /**
     * Function to print out an option element
     *
     * @return string
     */
    public function print_Option()
    {
        $type = strtolower($this->type) == 'iavm' ? strtoupper($this->type) : ucfirst($this->type);
        return "<option value='{$this->id}' " .
            "title='{$this->name} V{$this->ver}R{$this->release} ({$this->type})'>" .
            "{$this->name} V{$this->ver}R{$this->release} ({$type})</option>";
    }
}
