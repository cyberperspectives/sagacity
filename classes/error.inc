<?php
/**
 * File: error.inc
 * Author: Ryan Prather
 * Purpose: This file will contain the error handler for the ST&E Manager
 * Created: Jun 18, 2014
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
 *  - Jun 18, 2014 - File created
 *  - Jul 29, 2014 - Added script log functionality
 *  - Sep 05, 2014 - Fixed bug with realpath returning false for absent file
 *  - Oct 24, 2016 - Converted Sagacity_Error::E_DEBUG constant to global constant (define)
 * 					 Added "DEBUG" output to all functions
 *  - Nov 7, 2016 - Added timestamp to debug prints and updated copyright to include CP
 *  - Nov 9, 2016 - Changed err_handler to use sagacity.log and write to file using file_put_contents
 *  - Nov 16, 2016 - Changed sql_handler to write to file using file_put_contents
 *  - Dec 7, 2016 - Fixed sql_handler, err_handler, and script_log to only print out on E_DEBUG when using cli and use PHP_EOL
 *  - Mar 3, 2017 - Formatting
 *  - Mar 22, 2017 - Check that log file is writable in constructor
 *  - May 13, 2017 - Added check in script_log, err_handler, and sql_handler functions to check that LOG_LEVEL = E_DEBUG
 */

require 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

/**
 * Represents the error object to do error handling
 *
 * @author Ryan Prather
 */
class Sagacity_Error extends Logger
{

    /**
     * File handle
     *
     * @var resource
     */
    private $fh = null;

    /**
     * Log file name
     *
     * @var string
     */
    private $fname = '';

    /**
     * Constructor
     *
     * @param string $fname_in
     */
    public function __construct($fname_in)
    {
        $this->fname = preg_replace("/[\.][^\.]+$/", '', basename($fname_in));
        if (!file_exists(LOG_PATH . "/{$this->fname}.log")) {
            touch(LOG_PATH . "/{$this->fname}.log");
        }

        if (!is_writeable(LOG_PATH . "/{$this->fname}.log")) {
            self::err_handler("File " . realpath(LOG_PATH) . "/{$this->fname}.log is not writable", E_ERROR);
        }

        $log_level = Logger::ERROR;
        switch(LOG_LEVEL) {
            case E_WARNING:
                $log_level = Logger::WARNING;
                break;
            case E_NOTICE:
                $log_level = Logger::INFO;
                break;
            case E_DEBUG:
                $log_level = Logger::DEBUG;
                break;
        }

        $this->fh = new Logger($this->fname);
        $this->fh->pushHandler(new StreamHandler(LOG_PATH . "/{$this->fname}.log", $log_level));

        if(PHP_SAPI == 'cli') {
            $stream = new StreamHandler("php://output", $log_level);
            $stream->setFormatter(new LineFormatter("%datetime% %level_name% %message%\n", "H:i:s.u"));
            $this->fh->pushHandler($stream);
        }
    }

    /**
     * Function to write to SQL error log file
     *
     * @param string $sql
     *   SQL line that is the problem
     * @param integer $errno [optional]
     *   Error number (Default is E_NOTICE)
     */
    public static function sql_handler($sql, $errno = E_NOTICE)
    {
        if (!file_exists(LOG_PATH . "/sql_log")) {
            touch(LOG_PATH . "/sql_log");
        }
        $dt     = new DateTime();
        $errlvl = 'NOTICE';
        switch ($errno) {
            case E_USER_WARNING:
            case E_WARNING:
                $errlvl = "WARNING";
                break;
            case E_USER_ERROR:
            case E_ERROR:
                $errlvl = "ERROR";
                break;
            case E_DEBUG:
                $errlvl = "DEBUG";
                break;
            default:
        }

        $errmsg = "{$dt->format(DateTime::ISO8601)} - $errlvl - $sql" . PHP_EOL;

        file_put_contents(realpath(LOG_PATH . "/sql_log"), $errmsg, FILE_APPEND);

        if ($errno == E_ERROR) {
            die($sql . PHP_EOL);
        }
        elseif ($errno == E_DEBUG && LOG_LEVEL == E_DEBUG && substr(php_sapi_name(), 0, 3) == 'cli') {
            print $errmsg;
        }
    }

    /**
     * Function to write application error to log file
     *
     * @param string $errmsg
     *   Error message to write
     * @param integer $errno [optional]
     *   Error number (Default is E_NOTICE)
     */
    public static function err_handler($errmsg, $errno = E_NOTICE)
    {
        if (!file_exists(LOG_PATH . "/sagacity.log")) {
            touch(LOG_PATH . "/sagacity.log");
        }
        $dt  = new DateTime();
        $str = "{$dt->format(DateTime::ISO8601)} - ";
        switch ($errno) {
            case E_USER_WARNING:
            case E_WARNING:
                $str .= "WARNING";
                break;
            case E_USER_ERROR:
            case E_ERROR:
                $str .= "ERROR";
                break;
            case E_USER_NOTICE:
            case E_NOTICE:
                $str .= "NOTICE";
                break;
            case E_DEBUG:
                $str .= "DEBUG";
                break;
            default:
        }

        file_put_contents(realpath(LOG_PATH . "/sagacity.log"), "$str - $errmsg" . PHP_EOL, FILE_APPEND);

        if ($errno == E_ERROR || $errno == E_USER_ERROR) {
            die($errmsg . PHP_EOL);
        }
        if ($errno == E_DEBUG && LOG_LEVEL == E_DEBUG && substr(php_sapi_name(), 0, 3) == 'cli') {
            print "$str - $errmsg" . PHP_EOL;
        }
    }

    /**
     * Function to output a message to the script log file
     *
     * @param string $errmsg
     * @param integer $errno [optional]
     */
    public function script_log($errmsg, $errno = E_NOTICE)
    {
        if (!is_a($this->fh, "Monolog\Logger")) {
            return;
        }

        switch($errno) {
            case E_ERROR:
                $this->fh->error($errmsg);
                die;
                break;

            case E_WARNING:
                $this->fh->warning($errmsg);
                break;

            case E_NOTICE:
                $this->fh->info($errmsg);
                break;

            case E_DEBUG:
                $this->fh->debug($errmsg);
                break;

            default:
                $this->fh->emergency($errmsg);
                die;
        }
    }
}
