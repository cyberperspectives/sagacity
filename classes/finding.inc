<?php

/**
 * File: finding.inc
 * Author: Ryan Prather
 * Purpose: Represents a finding
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
 *  - Sep 1, 2016 - Updated Copyright and added comments to finding_status class
 *  - Nov 7, 2016 - Added finding::inc_Finding_Count function to increment counter
 *  - May 25, 2017 - Fixed bug of get_Category method returning empty severity (defaults to II if empty)
 *  - Jan 10, 2018 - Formatting
 *  - May 24, 2018 - Simplified get_Finding_Status_ID method
 *  - Nov 6, 2018 - Removed ID property to keep from duplicate findings
 */

/**
 * Represents a finding
 *
 * @author Ryan Prather
 *        
 */
class finding
{

    /**
     * Target ID
     *
     * @var integer
     */
    protected $tgt_id = null;

    /**
     * PDI ID
     *
     * @var integer
     */
    protected $pdi_id = null;

    /**
     * Scan ID
     *
     * @var integer
     */
    protected $scan_id = null;

    /**
     * Finding Status ID
     *
     * @var integer
     */
    protected $finding_status_id = null;

    /**
     * Updated category for the finding
     *
     * @var int
     */
    protected $cat = null;

    /**
     * Array of ia controls that apply to this finding
     *
     * @var array:string
     */
    protected $ia_controls = array();

    /**
     * Notes
     *
     * @var string
     */
    protected $notes = null;

    /**
     * Analyst Notes
     *
     * @var string
     */
    protected $analyst_notes = null;

    /**
     * Scanner Notes
     *
     * @var string
     */
    protected $scanner_notes = null;

    /**
     * Change ID
     *
     * @var integer
     */
    protected $change_id = null;

    /**
     * Original source
     *
     * @var string
     */
    protected $orig_src = null;

    /**
     * Finding iteration (incremented if finding is updated
     *
     * @var integer
     */
    protected $finding_itr = null;

    /**
     * Array of statuses
     *
     * @var array:string
     */
    protected $STATUS = [
        1 => 'Not Reviewed',
        2 => 'Not a Finding',
        3 => 'Open',
        4 => 'Not Applicable',
        5 => 'No Data',
        6 => 'Exception',
        7 => 'False Positive'
    ];

    /**
     * Constant for no change
     *
     * @var integer
     */
    const NC = 0;

    /**
     * Constant for change ID::TO_OPEN
     *
     * @var integer
     */
    const TO_OPEN = 1;

    /**
     * Constant for change ID::TO_NF
     *
     * @var integer
     */
    const TO_NF = 2;

    /**
     * Constant for change ID::TO_NA
     *
     * @var integer
     */
    const TO_NA = 3;

    /**
     * Constructor
     *
     * @param integer $int_Tgt_ID
     * @param integer $int_PDI_ID
     * @param integer $int_Scan_ID
     * @param integer|string $Finding_Status
     * @param string $str_Notes
     * @param integer $int_Change_ID
     * @param string $str_Orig_Src
     * @param integer $int_Finding_Itr
     */
    public function __construct($int_Tgt_ID, $int_PDI_ID, $int_Scan_ID, $Finding_Status, $str_Notes, $int_Change_ID, $str_Orig_Src, $int_Finding_Itr)
    {
        $this->tgt_id = $int_Tgt_ID;
        $this->pdi_id = $int_PDI_ID;
        $this->scan_id = $int_Scan_ID;
        if (is_numeric($Finding_Status)) {
            $this->finding_status_id = $Finding_Status;
        } else {
            $this->finding_status_id = $this->get_Finding_Status_ID($Finding_Status);
        }
        $this->notes = $str_Notes;
        $this->change_id = $int_Change_ID;
        $this->orig_src = $str_Orig_Src;
        $this->finding_itr = $int_Finding_Itr;
    }

    /**
     * Getter function for target ID
     *
     * @return integer
     */
    public function get_Tgt_ID()
    {
        return $this->tgt_id;
    }

    /**
     * Setter function for target ID
     *
     * @param integer $int_Tgt_ID
     */
    public function set_Tgt_ID($int_Tgt_ID)
    {
        $this->tgt_id = $int_Tgt_ID;
    }

    /**
     * Getter function for PDI ID
     *
     * @return integer
     */
    public function get_PDI_ID()
    {
        return $this->pdi_id;
    }

    /**
     * Setter function for PDI ID
     *
     * @param integer $int_PDI_ID
     */
    public function set_PDI_ID($int_PDI_ID)
    {
        $this->pdi_id = $int_PDI_ID;
    }

    /**
     * Getter function for Scan ID
     *
     * @return integer
     */
    public function get_Scan_ID()
    {
        return $this->scan_id;
    }

    /**
     * Setter function for Scan ID
     *
     * @param integer $int_Scan_ID
     */
    public function set_Scan_ID($int_Scan_ID)
    {
        $this->scan_id = $int_Scan_ID;
    }

    /**
     * Getter function for Finding status ID
     *
     * @return integer
     */
    public function get_Finding_Status()
    {
        return $this->finding_status_id;
    }

    /**
     * Getter function for Finding status ID based on string
     *
     * @param string $status
     * @return integer
     */
    public function get_Finding_Status_ID($status)
    {
        $arr_flip = array_flip($this->STATUS);
        if (isset($arr_flip[$status])) {
            return $arr_flip[$status];
        } else {
            return $arr_flip['Not Reviewed'];
        }
    }

    /**
     * Getter function for finding status string
     *
     * @param integer $int_Status_ID
     * @return string
     */
    public function get_Finding_Status_String($int_Status_ID = null)
    {
        if ($int_Status_ID) {
            return $this->STATUS[$int_Status_ID];
        } else {
            return $this->STATUS[$this->finding_status_id];
        }
    }

    /**
     * Setter function for finding status
     *
     * @param integer $int_Finding_Status_ID
     */
    public function set_Finding_Status($int_Finding_Status_ID)
    {
        $this->finding_status_id = $int_Finding_Status_ID;
    }

    /**
     * Setter function for finding status
     *
     * @param string $str_New_Status
     */
    public function set_Finding_Status_By_String($str_New_Status)
    {
        $this->finding_status_id = $this->get_Finding_Status_ID($str_New_Status);
    }

    /**
     * Getter function for notes
     *
     * @return string
     */
    public function get_Notes()
    {
        return $this->notes;
    }

    /**
     * Setter function for notes
     *
     * @param string $str_Notes
     */
    public function set_Notes($str_Notes)
    {
        $this->notes = $str_Notes;
    }

    /**
     * Function to prepend notes to the existing list
     *
     * @param string $str_Notes
     */
    public function prepend_Notes($str_Notes)
    {
        $this->notes = $str_Notes . PHP_EOL . $this->notes;
    }

    /**
     * Function to append notes
     *
     * @param string $str_Notes
     * @param boolean $merge
     */
    public function append_Notes($str_Notes, $merge = false)
    {
        $this->notes .= PHP_EOL . ($merge ? "(Merged Target)" . PHP_EOL : "") . $str_Notes;
    }

    /**
     * Getter function for the analyst notes
     *
     * @return string
     */
    public function get_Analyst_Notes()
    {
        return $this->analyst_notes;
    }

    /**
     * Setter function for the analyst notes
     *
     * @param string $str_Notes
     */
    public function set_Analyst_Notes($str_Notes)
    {
        $this->analyst_notes = $str_Notes;
    }
    
    /**
     * Getter function for the scanner notes
     * 
     * @return string
     */
    public function get_Scanner_Notes()
    {
        return $this->scanner_notes;
    }
    
    /**
     * Setter function for the scanner notes
     * 
     * @param string $str_Notes
     */
    public function set_Scanner_Notes($str_Notes)
    {
        $this->scanner_notes = $str_Notes;
    }

    /**
     * Getter function for change ID
     *
     * @return integer
     */
    public function get_Change_ID()
    {
        if ($this->change_id) {
            return $this->change_id;
        } else {
            return $this::NC;
        }
    }

    /**
     * Setter function for change ID
     *
     * @param integer $int_Change_ID
     */
    public function set_Change_ID($int_Change_ID)
    {
        $this->change_id = $int_Change_ID;
    }

    /**
     * Getter function for original source
     *
     * @return string
     */
    public function get_Original_Source()
    {
        return $this->orig_src;
    }

    /**
     * Setter function for original source
     *
     * @param string $str_Original_Source
     */
    public function set_Original_Source($str_Original_Source)
    {
        $this->orig_src = $str_Original_Source;
    }

    /**
     * Getter function for finding iteration
     *
     * @return integer
     */
    public function get_Finding_Iteration()
    {
        return $this->finding_itr;
    }

    /**
     * Setter function for finding iteration
     *
     * @param integer $int_Finding_Iteration
     */
    public function set_Finding_Iteration($int_Finding_Iteration)
    {
        $this->finding_itr = $int_Finding_Iteration;
    }

    /**
     * Increment the finding count by 1
     */
    public function inc_Finding_Count()
    {
        $this->finding_itr ++;
    }

    /**
     * Getter function for deconflicted status
     *
     * @param string $str_New_Status
     * @return string
     */
    public function get_Deconflicted_Status($str_New_Status)
    {
        // must get original status first!
        return deconflict_status::$DECONFLICTED_STATUS[$this->get_Finding_Status_String()][$str_New_Status];
    }

    /**
     * Getter function for category
     *
     * @return int
     */
    public function get_Category()
    {
        if (empty($this->cat)) {
            return 2;
        }
        return $this->cat;
    }

    /**
     * Setter function for category
     *
     * @param mixed $cat_in
     */
    public function set_Category($cat_in)
    {
        if (is_numeric($cat_in)) {
            $this->cat = $cat_in;
        } elseif (is_string($cat_in)) {
            $this->cat = substr_count($cat_in, "I");
        }
    }

    /**
     * Getter function for IA controls
     *
     * @return array:string
     */
    public function get_IA_Controls()
    {
        return $this->ia_controls;
    }

    /**
     * Getter function for IA Controls
     *
     * @return string
     */
    public function get_IA_Controls_String()
    {
        return implode(" ", $this->ia_controls);
    }

    /**
     * Setter function for the IA Controls
     *
     * @param mixed $ia_controls_in
     */
    public function set_IA_Controls($ia_controls_in)
    {
        if (is_array($ia_controls_in)) {
            $this->ia_controls = $ia_controls_in;
        } elseif (is_string($ia_controls_in)) {
            $this->ia_controls = explode(" ", $ia_controls_in);
        }
    }

    /**
     * Function to add an IA control the the array
     *
     * @param string $ia_control_in
     */
    public function add_IA_Control($ia_control_in)
    {
        $add = true;
        foreach ($this->ia_controls as $ia) {
            if ($ia == $ia_control_in) {
                $add = false;
                break;
            }
        }

        if ($add) {
            $this->ia_controls[] = $ia_control_in;
        }
    }
}

/**
 * The finding status
 *
 * @author Ryan Prather
 */
class finding_status
{

    /**
     * The database ID of the finding status
     *
     * @var int
     */
    public $id = 0;

    /**
     * The status of the finding
     *
     * @var string
     */
    public $status = '';
}

/**
 * Class to deconflict statuses
 *
 * @author Ryan Prather
 */
class deconflict_status
{

    /**
     * Stores the matrix of current -> new statuses
     *
     * @var array:string / Finding Definitions
     *      Open: The finding is valid for this host - the host does not meet the requirements
     *      Not a Finding: The finding is not valid for this host - the host meets the requirements
     *      Not Applicable: The requirement does not apply to this host - prerequisites do not exist.
     *      Not Reviewed: The finding has not yet been reviewed.
     *      Exception: (A type of Open) - The finding is valid, but the system cannot comply for a valid reason
     *      False Positive: (A type of Not a Finding) - The scanning tool incorrectly reported Open.
     *      No Data: Because dissimilar checklists were merged, there is no data available for this item (Uncommon)
     *     
     *      General Precedence Order: E, FP, O, NF, NA, NR, ND
     *      Exception - the newest E or FP always take precedence (security engineer input)
     *     
     *      Decision Table:
     *      orig\new | E | FP | O | NF | NA | NR | ND
     *      E | E | FP | E | E | E | E | E
     *      FP | E | FP | FP | FP | FP | FP | FP
     *      O | E | FP | O | O | O | O | O
     *      NF | E | FP | O | NF | NF | NF | NF
     *      NA | E | FP | O | NF | NA | NA | NA
     *      NR | E | FP | O | NF | NA | NR | NR
     *      ND | E | FP | O | NF | NA | NR | ND
     */
    static $DECONFLICTED_STATUS = [
        'Exception' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'Exception',
            'Not a Finding' => 'Exception',
            'Not Applicable' => 'Exception',
            'Not Reviewed' => 'Exception',
            'No Data' => 'Exception'
        ],
        'False Positive' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'False Positive',
            'Not a Finding' => 'False Positive',
            'Not Applicable' => 'False Positive',
            'Not Reviewed' => 'False Positive',
            'No Data' => 'False Positive'
        ],
        'Open' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'Open',
            'Not a Finding' => 'Open',
            'Not Applicable' => 'Open',
            'Not Reviewed' => 'Open',
            'No Data' => 'Open'
        ],
        'Not a Finding' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'Open',
            'Not a Finding' => 'Not a Finding',
            'Not Applicable' => 'Not a Finding',
            'Not Reviewed' => 'Not a Finding',
            'No Data' => 'Not a Finding'
        ],
        'Not Applicable' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'Open',
            'Not a Finding' => 'Not a Finding',
            'Not Applicable' => 'Not Applicable',
            'Not Reviewed' => 'Not Applicable',
            'No Data' => 'Not Applicable'
        ],
        'Not Reviewed' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'Open',
            'Not a Finding' => 'Not a Finding',
            'Not Applicable' => 'Not Applicable',
            'Not Reviewed' => 'Not Reviewed',
            'No Data' => 'Not Reviewed'
        ],
        'No Data' => [
            'Exception' => 'Exception',
            'False Positive' => 'False Positive',
            'Open' => 'Open',
            'Not a Finding' => 'Not a Finding',
            'Not Applicable' => 'Not Applicable',
            'Not Reviewed' => 'Not Reviewed',
            'No Data' => 'No Data'
        ]
    ];
}
