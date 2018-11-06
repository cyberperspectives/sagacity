<?php
/**
 * File: host_list.inc
 * Author: Ryan Prather
 * Purpose: Represents an imported scan
 * Created: Jan 16, 2018
 *
 * Copyright 2016-2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 * - Jan 16, 2018 - File created
 * - Feb 6, 2018 - Added getter/setter methods
 * - Nov 6, 2018 - Deleted unused constructor
 */

/**
 * Description of host_list
 *
 * @author Ryan Prather
 */
class host_list
{

    /**
     * Target ID
     *
     * @var integer
     */
    private $_targetId = 0;

    /**
     * Target name
     *
     * @var string
     */
    private $_targetName = null;

    /**
     * Target IP address
     *
     * @var string
     */
    private $_targetIp = null;

    /**
     * Number of findings for this target
     *
     * @var integer
     */
    private $_findingCount = 0;

    /**
     * Was there an error when scanning the target
     *
     * @var boolean
     */
    private $_scanError = false;

    /**
     * Are their any special notes for the target
     *
     * @var string
     */
    private $_scanNotes = null;

    /**
     * Getter function for _targetId
     *
     * @return int
     */
    public function getTargetId()
    {
        return $this->_targetId;
    }

    /**
     * Setter function for _targetId
     *
     * @param int $intTargetId
     */
    public function setTargetId($intTargetId)
    {
        $this->_targetId = $intTargetId;
    }

    /**
     * Getter function for _targetName
     *
     * @return string
     */
    public function getTargetName()
    {
        return $this->_targetName;
    }

    /**
     * Setter function for _targetName
     *
     * @param string $strTargetName
     */
    public function setTargetName($strTargetName)
    {
        $this->_targetName = $strTargetName;
    }

    /**
     * Getter function for _targetIp
     *
     * @return string
     */
    public function getTargetIp()
    {
        return $this->_targetIp;
    }

    /**
     * Setter function for _targetIp
     *
     * @param string $strTargetIp
     */
    public function setTargetIp($strTargetIp)
    {
        $this->_targetIp = $strTargetIp;
    }

    /**
     * Getter function for _findingCount
     *
     * @return int
     */
    public function getFindingCount()
    {
        return $this->_findingCount;
    }

    /**
     * Setter function for _findingCount
     *
     * @param int $intFindingCount
     */
    public function setFindingCount($intFindingCount)
    {
        $this->_findingCount = $intFindingCount;
    }

    /**
     * Getter function for _scanError
     *
     * @return bool
     */
    public function getScanError()
    {
        return $this->_scanError;
    }

    /**
     * Setter function for _scanError
     *
     * @param bool $blnScanError
     */
    public function setScanError($blnScanError)
    {
        $this->_scanError = $blnScanError;
    }

    /**
     * Getter function for _scanNotes
     *
     * @return string
     */
    public function getScanNotes()
    {
        return $this->_scanNotes;
    }

    /**
     * Setter function for _scanNotes
     *
     * @param string $strScanNotes
     */
    public function setScanNotes($strScanNotes)
    {
        $this->_scanNotes = $strScanNotes;
    }
}
