<?php
/*
 * File: DateTimeDiff.php
 * Purpose: File to calculate DateTime differences
 * Author: Ryan Prather
 * Created: Feb 23, 2018
 *
 * Copyright 2018: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 * - Feb 23, 2018 - File Created
 * - Apr 29, 2018 - Added return for formatted date/time string for start and stop
 */

/**
 * Class to automagically calculate time differences
 *
 * @author godsg
 */
class DateTimeDiff
{

    /**
     * The starting clock
     *
     * @var DateTime
     */
    private $_dtStart = null;

    /**
     * The ending clock
     *
     * @var DateTime
     */
    private $_dtEnd = null;

    /**
     * Variable to store difference between _dtEnd - _dtStart
     *
     * @var DateInterval
     */
    private $_diff = null;

    /**
     * Variable to store total time difference
     *
     * @var DateInterval
     */
    private $_totalDiff = null;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->_dtStart = new DateTime();
    }

    /**
     * Getter function for _dtStart
     *
     * @return DateTime
     */
    public function getStartClock()
    {
        return $this->_dtStart;
    }

    /**
     * Getter function for _dtStart as formatted time
     *
     * @return string
     */
    public function getStartClockTime()
    {
        return $this->_dtStart->format("H:i:s");
    }

    /**
     * Getter function for _dtStart as formatted date/time
     *
     * @return string
     */
    public function getStartClockDateTime()
    {
        return $this->_dtStart->format(MYSQL_DT_FORMAT);
    }

    /**
     * Getter function for _dtEnd
     *
     * @return DateTime
     */
    public function getEndClock()
    {
        return $this->_dtEnd;
    }

    /**
     * Getter function for _dtEnd as formatted time
     *
     * @return string
     */
    public function getEndClockTime()
    {
        return $this->_dtEnd->format("H:i:s");
    }

    /**
     * Getter function for _dtEnd as formatted date/time
     * 
     * @return string
     */
    public function getEndClockDateTime()
    {
        return $this->_dtEnd->format(MYSQL_DT_FORMAT);
    }

    /**
     * Function to stop the clock and set the ending time
     */
    public function stopClock()
    {
        $this->_dtEnd = new DateTime();

        $this->updateDiff();
        $this->updateTotalDiff();

    }

    /**
     * Function to reset the starting clock for another difference
     */
    public function resetClock()
    {
        $this->_dtStart = new DateTime();
    }

    /**
     * Function to set the difference
     */
    public function updateDiff()
    {
        $this->_diff = $this->_dtEnd->diff($this->_dtStart);
    }

    /**
     * Getter function for _diff
     *
     * @return DateInterval
     */
    public function getDiff()
    {
        return $this->_diff;
    }

    /**
     * Function to return _diff as a formatting string
     *
     * @return string
     */
    public function getDiffString()
    {
        return $this->_diff->format("%H:%I:%S");
    }

    /**
     * Function to update the total difference
     */
    public function updateTotalDiff()
    {
        $this->_totalDiff = $this->addIntervals();
    }

    /**
     * Getter function for _totalDiff
     *
     * @return DateInterval
     */
    public function getTotalDiff()
    {
        return $this->_totalDiff;
    }

    /**
     * Function to return to _totalDiff as a formatted string
     *
     * @return string
     */
    public function getTotalDiffString()
    {
        return $this->_totalDiff->format("%H:%I:%S");
    }

    /**
     * Function to add two DateIntervals together and return the difference result
     *
     * @return DateInterval
     */
    public function addIntervals()
    {
        $a = new DateTime("00:00");
        $b = clone $a;

        if (is_a($this->_totalDiff, 'DateInterval')) {
          $a->add($this->_totalDiff);
        }

        if (is_a($this->_diff, 'DateInterval')) {
          $a->add($this->_diff);
        }

        return $b->diff($a);
    }

}
