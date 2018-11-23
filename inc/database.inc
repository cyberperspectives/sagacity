<?php
/**
 * File: database.inc
 * Author: Ryan Prather
 * Purpose: This file will contain all the variables and functions to operate a database
 *  and for the ST&E Manager to interact with
 * Created: Sep 11, 2013
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
 *  - Sep 11, 2013 - File created
 *  - Sep 1, 2016 - Copyright Updated, way to many updates to list
 *  - Oct 24, 2016 - Updated delete_Scan function to check for return of scan array
 * 					 Changed SQL updating host list to REPLACE instead (fixes updating the finding count)
 * 					 Added get_Running_Script_Status function to return the status of the script
 * 					 Added is_Connected function to check the status of the DB connection (and reconnect if there are issues)
 * 					 Updated tcp/udp_port variable to use functions instead
 *  - Nov 7, 2016 - Several changes when getting and saving tcp/udp port data
 *  - Nov 16, 2016 - Changed error for failed DB connect to include attempted server
 *  - Jan 30, 2017 - Formatting
 *  - Jan 31, 2017 - Cleaned up db_helper functionality
 *  - Feb 15, 2017 - Started process to migrate some query to be created with the db_helper class and fixed a couple bugs
 *  - Mar 3, 2017 - Added IS and NOT_LIKE defined constants, added check if ` or AS is present, then not adding a `,
 *                  Documentation, Fixed error in db_helper::order method, Started converting db class methods to use db_helper
 *  - Mar 8, 2017 - Converted a couple more queries to use db_helper object and formatting
 *  - Mar 13, 2017 - Fixed bugs with db_helper::where functions and added fields function
 *  - Mar 14, 2017 - Fixed bug in db::get_Software method
 *  - Mar 20, 2017 - Updated CCE and CCI methods to use db_helper object
 *  - Mar 22, 2017 - Updated get_Nessus save_Nessus method to use db_helper object,
 *                   Fixed bug in db_helper::debug and db::get_Checklist
 *  - Apr 5, 2017 - Converted a few other methods to use db_helper class, switch positions for parameters in db::save_Target method,
 *                  Added documentation in a few places, fixed bug with Nessus parsing
 *  - Apr 7, 2017 - Replaced function get_STE_Category_List with get_STE_Cat_List (and updated required files),
 *                  Converted more methods to use db_helper, fixed a couple typos (add_Source -> add_Sources),
 *                  Changed save_Target to save the short_sw_string as the os_string instead
 *  - Apr 10, 2017 - More db_helper conversions and bug fixes
 *  - May 13, 2017 - Always lots of changes here
 *                   Added get_Checklist_By_Filename method
 *                   Converted get_Category_Checklists function to use db_helper class
 *                   Converted save_SV_Rule method to use db_helper class
 *                   Converted over a few other methods to use db_helper class
 *  - May 19, 2017 - Converted over more methods to use db_helper class
 *                   Fixed typo, added deleting category interview data when deleting category
 *  - May 22, 2017 - Simplified get_ScanData function to not retrieve all data for target host lists (took too much time)
 *                   Converted save_IA_Controls method to use db_helper class
 *  - May 25, 2017 - Added 'start' flag to db_helper::flags method to start at a different record (supporting paging in DataTables library)
 *                   Converted over a couple methods to use db_helper class
 *  - Jun 27, 2017 - Set default target classification if not present, fixed bug #264
 *  - Jul 13, 2017 - Revised several method to use db_helper class and removed db::add_PDI method and moved to just using save_PDI method
 *  - Jul 21, 2017 - Cleaned up port saving in save_Interface method
 *  - Jul 24, 2017 - Added save_EMASS_CCIs() and get_EMASS_CCIs() to create and retrieve the rmf.emass_cci table
 *  - Aug 28, 2017 - Fixed typo w/cve_reference table #276
 *  - Aug 28, 2017 - Added delete_Target_Software, fixed error when deleting all software or checklists (wouldn't save correctly), and cleaned up delete_Target method
 *  - Oct 26, 2017 - Formatting and bug fix for #326
 *  - Oct 27, 2017 - Change filtering for get_ports, added delete_Interface method
 *  - Dec 27, 2017 - Migrate methods to use db_helper and syntax updates
 *  - Jan 1, 2018 - Added get_Software_Id method that gets all the software IDs from a list of CPEs
 *  - Jan 10, 2018 - Added a couple functions and formatting
 *  - Jan 15, 2018 - Fixed bug in get_Category_Findings
 *  - Jan 16, 2018 - Added include for host_list.inc, updated to use host_list class, fixed bug in delete_Scan method
 Moved scan deletion here
 *  - Jan 20, 2018 - Fixed typo in save_STE method
 *  - May 24, 2018 - Added defaulting where clause operator to '='
 *  - May 26, 2018 - Updated autocategorization to removed any extranious spaces before or after the string
 *  - May 31, 2018 - Changes to support renaming sagacity.pdi_catalog.check_content field and scan error detection
 *  - Jun 2, 2018 - Formatting and added set_Setting_Array method
 *  - Jun 5, 2018 - Changed set_Setting_Array method to use SQL update instead of replace
 *  - Sep 5, 2018 - Fix for #8
 *  - Nov 3, 2018 - Fix for fix #62, commented out last INSERT in post_Processing, jao
 *  - Nov 8, 2018 - Added a couple methods to support changes for #25
 */
include_once 'base.inc';
include_once 'software.inc';
include_once 'checklist.inc';
include_once 'ste.inc';
include_once 'target.inc';
include_once 'scan.inc';
include_once 'pdi_catalog.inc';
include_once 'port.inc';
include_once 'sites.inc';
include_once 'sources.inc';
include_once 'ste_cat.inc';
include_once 'system.inc';
include_once 'interfaces.inc';
include_once 'script.inc';
include_once 'stigs.inc';
include_once 'golddisk.inc';
include_once 'finding.inc';
include_once 'ia_control.inc';
include_once 'retina.inc';
include_once 'sv_rule.inc';
include_once 'nessus.inc';
include_once 'echecklist.inc';
include_once 'cve.inc';
include_once 'advisories.inc';
include_once 'iavm.inc';
include_once 'oval.inc';
include_once 'cce.inc';
include_once 'proc_ia_controls.inc';
include_once 'error.inc';
include_once 'question.inc';
include_once 'cci.inc';
include_once 'rmf_control.inc';
include_once 'cpe.inc';
include_once 'nasl.inc';
include_once 'uuid.inc';
include_once 'host_list.inc';

// @TODO - Make sure all save functions accept a class object or array of that class that is being saved. Otherwise, only primative types will be passed in.
/**
 * Constant to decide if the database queries will run automatically after creating them
 *
 * @var boolean
 */
define('AUTORUN', false);

/**
 * Global to represent an IN statement (e.g.
 * WHERE field IN (1,2))
 *
 * @var int
 */
define('IN', 1);

/**
 * Global to represent a NOT IN statement (e.g.
 * WHERE field NOT IN (1,2))
 *
 * @var int
 */
define('NOT_IN', 64);

/**
 * Global to represent a BETWEEN statement (e.g.
 * WHERE field BETWEEN 1 and 2)
 *
 * @var int
 */
define('BETWEEN', 2);

/**
 * Global to represent a LIKE statement (e.g.
 * WHERE field LIKE '%value%')
 *
 * @var int
 */
define('LIKE', 4);

/**
 * Global to represent an IS NOT statement (e.g.
 * WHERE field IS NOT NULL)
 *
 * @var int
 */
define('IS_NOT', 8);

/**
 * Global to represent an IS statement (e.g.
 * WHERE field IS NULL)
 *
 * @var int
 */
define('IS', 16);

/**
 * Global to represent an NOT LIKE statement (e.g.
 * WHERE field NOT LIKE '%value%'
 *
 * @var int
 */
define('NOT_LIKE', 32);

/**
 * Class to help the database
 *
 * @author Ryan Prather
 */
class db_helper
{

    const SELECT = 1;

    const SELECT_COUNT = 2;

    const CREATE_TABLE = 3;

    const DROP = 4;

    const DELETE = 5;

    const INSERT = 6;

    const REPLACE = 7;

    const UPDATE = 8;

    const EXTENDED_INSERT = 9;

    const EXTENDED_REPLACE = 10;

    const EXTENDED_UPDATE = 11;

    const ALTER_TABLE = 12;

    const TRUNCATE = 13;

    /**
     * The mysqli connection
     *
     * @var mysqli
     */
    public $c;

    /**
     * To store the SQL statement
     *
     * @var string
     */
    public $sql = null;

    /**
     * A string to store the type of query that is being run
     *
     * @var string
     */
    public $query_type = null;

    /**
     * The result of the query
     *
     * @var mixed
     */
    private $result = null;

    /**
     * Constructor
     *
     * @param mysqli $dbh
     *            [by ref]
     *            mysqli object to perform queries.
     */
    public function __construct(&$dbh)
    {
        if (! is_null($dbh) && is_a($dbh, "mysqli")) {
            $this->c = $dbh;
        } else {
            throw (new Exception("Could not create database helper class", E_ERROR));
        }

        $this->c->real_query("SET time_zone='+00:00'");
        $this->c->real_query("SET sql_mode=''");
    }

    /**
     * Function to execute the statement
     *
     * @param mixed $return
     *            [optional]
     *            MYSQLI constant to control what is returned from the mysqli_result object
     * @param string $sql
     *            [optional]
     *            Optional SQL query
     *
     * @return mixed
     */
    public function execute($return = MYSQLI_ASSOC, $sql = null)
    {
        if (! is_null($sql)) {
            $this->sql = $sql;
        }

        if (is_a($this->c, 'mysqli')) {
            if (! $this->c->ping()) {
                $this->c = null;
                $this->c = new mysqli(DB_SERVER, 'web', db::decrypt_pwd(), 'sagacity');
            }
        } else {
            throw (new Exception('Database was not connected', E_ERROR));
        }

        try {
            if (in_array($this->query_type, [
                self::SELECT,
                self::SELECT_COUNT
            ])) {
                $this->result = $this->c->query($this->sql);
                if ($this->c->error) {
                    $this->debug(E_ERROR);
                }
            } elseif ($this->query_type == self::DELETE) {
                $this->c->real_query($this->sql);
                if ($this->c->error) {
                    return 0;
                }
            } else {
                $this->c->real_query($this->sql);
                if ($this->c->error) {
                    $this->debug(E_ERROR, $this->c->error);
                }
            }

            $this->result = $this->check_results($return);
        } catch (Exception $e) {
            die($e->getTraceAsString());
        }

        return $this->result;
    }

    /**
     * Function to check the results and return what is expected
     *
     * @param mixed $return_type
     *            [optional]
     *            Optional return mysqli_result return type
     *
     * @return mixed
     */
    function check_results($return_type = MYSQLI_ASSOC)
    {
        $res = null;

        if ($this->c->error) {
            $this->debug(E_ERROR);
        } elseif (LOG_LEVEL == E_DEBUG) {
            $this->debug(E_DEBUG);
        }

        switch ($this->query_type) {
            case self::SELECT_COUNT:
                if (! is_a($this->result, 'mysqli_result')) {
                    $this->debug(E_ERROR);
                }

                if ($this->result->num_rows == 1) {
                    $res = $this->result->fetch_assoc()['count'];
                } elseif ($this->result->num_rows > 1) {
                    $res = $this->result->num_rows;
                }

                mysqli_free_result($this->result);

                return $res;
            case self::SELECT:
                if (! is_a($this->result, 'mysqli_result')) {
                    $this->debug(E_ERROR);
                }

                if ($this->result->num_rows == 1) {
                    $res = $this->result->fetch_array($return_type);
                } elseif ($this->result->num_rows > 1) {
                    $res = $this->fetch_all($return_type);
                }

                mysqli_free_result($this->result);

                return $res;
            case self::INSERT:
                if ($this->c->error) {
                    $this->debug(E_ERROR);
                    return 0;
                }

                if ($this->c->insert_id) {
                    return $this->c->insert_id;
                } elseif ($this->c->affected_rows) {
                    return $this->c->affected_rows;
                }

                return 1;
            case self::EXTENDED_INSERT:
            case self::EXTENDED_REPLACE:
            case self::EXTENDED_UPDATE:
            case self::REPLACE:
            case self::UPDATE:
            case self::DELETE:
            case self::ALTER_TABLE:
                if ($this->c->error && $this->c->errno == 1060) {
                    return ($this->c->affected_rows ? $this->c->affected_rows : true);
                } elseif ($this->c->error) {
                    $this->debug(E_ERROR);
                    return false;
                } elseif ($this->c->affected_rows) {
                    return $this->c->affected_rows;
                } else {
                    return true;
                }

                break;
            case self::CREATE_TABLE:
            case self::DROP:
            case self::TRUNCATE:
                return true;
        }
    }

    /**
     * Function to pass through calling the query function (used for backwards compatibility and for more complex queries that aren't currently supported)
     *
     * @param string $sql
     *            [optional]
     *            Optional query to pass in and execute
     *
     * @return mysqli_result
     */
    public function query($sql = null)
    {
        if (is_null($sql)) {
            return $this->c->query($this->sql);
        } else {
            return $this->c->query($sql);
        }
    }

    /**
     * A function to build a select query
     *
     * @param string $table_name
     *            The table to query
     * @param array $fields
     *            [optional]
     *            Optional array of fields to return (defaults to '*')
     * @param array $where
     *            [optional]
     *            Optional 2-dimensional array to build where clause from
     * @param array $flags
     *            [optional]
     *            Optional 2-dimensional array to allow other flags
     *
     * @see db_helper::where()
     * @see db_helper::flags()
     *
     * @return mixed
     */
    public function select($table_name, $fields = null, $where = null, $flags = null)
    {
        $this->sql = null;
        $this->query_type = self::SELECT;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "SELECT " . $this->fields($fields) . " FROM $table_name";
        } else {
            return null;
        }

        if (isset($flags['table_joins']) && is_array($flags['table_joins'])) {
            $this->sql .= " " . implode(" ", $flags['table_joins']);
        }

        if (! is_null($where) && is_array($where) && count($where)) {
            $this->sql .= $this->where($where);
        }

        if (! is_null($flags) && is_array($flags) && count($flags)) {
            $this->sql .= $this->flags($flags);
        }

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to build a query to check the number of rows in a table
     *
     * @param string $table_name
     *            The table to query
     * @param array $where
     *            [optional]
     *            Optional 2-dimensional array to build where clause
     * @param array $flags
     *            [optional]
     *            Optional 2-dimensional array to add flags
     *
     * @see db_helper::where()
     * @see db_helper::flags()
     *
     * @return string|NULL
     */
    public function select_count($table_name, $where = null, $flags = null)
    {
        $this->sql = null;
        $this->query_type = self::SELECT_COUNT;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "SELECT COUNT(1) AS 'count' FROM $table_name";
        } else {
            return null;
        }

        if (isset($flags['table_joins']) && is_array($flags['table_joins'])) {
            $this->sql .= " " . implode(" ", $flags['table_joins']);
        }

        if (! is_null($where) && is_array($where) && count($where)) {
            $this->sql .= $this->where($where);
        }

        if (! is_null($flags) && is_array($flags) && count($flags)) {
            $this->sql .= $this->flags($flags);
        }

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to build an insert query statement
     *
     * @param string $table_name
     *            Table name to query
     * @param array $params
     *            Name/value pair to insert into the table
     * @param boolean $to_ignore
     *            [optional]
     *            Optional boolean to decide if the "IGNORE" will be added
     *
     * @return string|NULL
     */
    public function insert($table_name, $params, $to_ignore = false)
    {
        $this->sql = null;
        $this->query_type = self::INSERT;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "INSERT " . ($to_ignore ? "IGNORE " : "") . "INTO $table_name " . "(`" . implode("`,`", array_keys($params)) . "`)";
        }

        $this->sql .= " VALUES (" . implode(",", array_map([
            $this,
            '_escape'
        ], array_values($params))) . ")";

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to create an extended insert query statement
     *
     * @param string $table_name
     *            The table name that the data is going to be inserted on
     * @param array $fields
     *            An array of field names that each value represents
     * @param array $params
     *            An array of array of values
     * @param boolean $to_ignore
     *            [optional]
     *            Boolean to decide if we need to use the INSERT IGNORE INTO syntax
     *
     * @return NULL|string Returns the SQL if AUTORUN is set to false, else it returns the output from running.
     */
    public function extended_insert($table_name, $fields, $params, $to_ignore = false)
    {
        $this->sql = null;
        $this->query_type = self::EXTENDED_INSERT;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "INSERT " . ($to_ignore ? "IGNORE " : "") . "INTO $table_name " . "(`" . implode("`,`", $fields) . "`)";
        } else {
            throw (new Exception("Missing table name in extended_insert", E_ERROR));
        }

        if (is_array($params) && count($params)) {
            $this->sql .= " VALUES ";
            if (isset($params[0]) && is_array($params[0])) {
                foreach ($params as $p) {
                    $this->sql .= "(" . implode(",", array_map([
                        $this,
                        '_escape'
                    ], array_values($p))) . "),";
                }
            } else {
                if (count($params) != count($fields)) {
                    throw (new Exception("Inconsistent number of fields in fields and values"));
                }
                $this->sql .= "(" . implode("),(", array_map([
                    $this,
                    '_escape'
                ], array_values($params))) . "),";
            }
        } else {
            throw new \InvalidArgumentException("Expected array parameters");
        }

        $this->sql = substr($this->sql, 0, - 1);

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Build a statement to update a table
     *
     * @param string $table_name
     *            The table name to update
     * @param array $params
     *            Name/value pairs of the field name and value
     * @param array $where
     *            [optional]
     *            Two-dimensional array to create where clause
     * @param array $flags
     *            [optional]
     *            Two-dimensional array to create other flag options (table_joins, order, and group)
     *
     * @see db_helper::where()
     * @see db_helper::flags()
     *
     * @return NULL|string
     */
    public function update($table_name, $params, $where = null, $flags = null)
    {
        $this->sql = "UPDATE ";
        $this->query_type = self::UPDATE;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql .= $table_name;

            if (isset($flags['table_joins'])) {
                $this->sql .= " " . implode(" ", $flags['table_joins']);
                unset($flags['table_joins']);
            }

            $this->sql .= " SET ";
        }

        foreach ($params as $f => $p) {
            if ((strpos($f, "`") === false) && (strpos($f, ".") === false) && (strpos($f, "*") === false) && (stripos($f, " as ") === false)) {
                $f = "`{$f}`";
            }

            if (! is_null($p)) {
                $this->sql .= "$f={$this->_escape($p)},";
            } else {
                $this->sql .= "$f=NULL,";
            }
        }

        $this->sql = substr($this->sql, 0, - 1);

        if (! is_null($where) && is_array($where) && count($where)) {
            $this->sql .= $this->where($where);
        }

        if (! is_null($flags) && is_array($flags) && count($flags)) {
            $this->sql .= $this->flags($flags);
        }

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to offer an extended updated functionality by using two different tables.
     *
     * @param string $to_be_updated
     *            The table that you want to update (alias 'tbu' is automatically added)
     * @param string $original
     *            The table with the data you want to overwrite to_be_updated table (alias 'o' is automatically added)
     * @param string $using
     *            The common index value between them that will join the fields
     * @param array|string $params
     *            If string only a single field is updated (tbu.$params = o.$params)
     *            If array each element in the array is a field to be updated (tbu.$param = o.$param)
     *
     * @return mixed
     */
    public function extended_update($to_be_updated, $original, $using, $params)
    {
        $this->sql = "UPDATE ";
        $this->query_type = self::EXTENDED_UPDATE;

        if (! is_null($to_be_updated) && ! is_null($original) && ! is_null($using)) {
            $this->sql .= "$to_be_updated tbu INNER JOIN $original o USING ($using) SET ";
        }

        if (is_array($params) && count($params)) {
            foreach ($params as $param) {
                $this->sql .= "tbu.$param = o.$param,";
            }
            $this->sql = substr($this->sql, 0, - 1);
        } elseif (is_string($params)) {
            $this->sql .= "tbu.$params = o.$params";
        } else {
            throw (new Exception("Do not understand datatype of \$params", E_ERROR));
        }

        if (AUTORUN) {
            return $this->execute(MYSQL_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to build a replace query
     *
     * @param string $table_name
     *            The table to update
     * @param array $params
     *            Name/value pair to insert
     *
     * @return NULL|string
     */
    public function replace($table_name, $params)
    {
        $this->sql = null;
        $this->query_type = self::REPLACE;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "REPLACE INTO $table_name " . "(`" . implode("`,`", array_keys($params)) . "`)";
        }

        $this->sql .= " VALUES (" . implode(",", array_map(array(
            $this,
            '_escape'
        ), array_values($params))) . ")";

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to build an extended replace statement
     *
     * @param string $table_name
     *            Table name to update
     * @param array $fields
     *            Array of fields
     * @param array $params
     *            Two-dimensional array of values
     *
     * @return NULL|string
     */
    public function extended_replace($table_name, $fields, $params)
    {
        $this->sql = null;
        $this->query_type = self::EXTENDED_REPLACE;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "REPLACE INTO $table_name " . "(`" . implode("`,`", $fields) . "`)";
        } else {
            return null;
        }

        if (is_array($params) && count($params)) {
            $this->sql .= " VALUES ";
            foreach ($params as $p) {
                $this->sql .= "(" . implode(",", array_map(array(
                    $this,
                    '_escape'
                ), array_values($p))) . "),";
            }
        }

        $this->sql = substr($this->sql, 0, - 1);

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to build a delete statement
     *
     * @param string $table_name
     *            Table name to act on
     * @param array $fields
     *            [optional]
     *            Optional list of fields to delete (used when including multiple tables)
     * @param array $where
     *            [optional]
     *            Optional 2-dimensional array to build where clause from
     * @param array $table_joins
     *            [optional]
     *            Optional 2-dimensional array to add other flags
     *
     * @see db_helper::where()
     * @see db_helper::flags()
     *
     * @return string|NULL
     */
    public function delete($table_name, $fields = null, $where = null, $table_joins = null)
    {
        $this->sql = "DELETE";
        $this->query_type = self::DELETE;

        if (! is_null($fields) && is_array($fields)) {
            $this->sql .= " " . implode(",", $fields);
        }

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql .= " FROM $table_name";
        } else {
            throw (new Exception("Failed to create delete query, no table name"));
        }

        if (! is_null($table_joins) && is_array($table_joins) && count($table_joins)) {
            $this->sql .= " " . implode(" ", $table_joins);
        }

        if (! is_null($where) && is_array($where) && count($where)) {
            $this->sql .= $this->where($where);
        }

        if (AUTORUN) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->sql;
    }

    /**
     * Function to build a drop table statement (automatically executes)
     *
     * @param string $schema
     *            Schema the table resides in
     * @param string $table_name
     *            Table to drop
     * @param boolean $is_tmp
     *            [optional]
     *            Optional boolean if this is a temporary table
     *
     * @return string|NULL
     */
    public function drop($schema, $table_name, $is_tmp = false)
    {
        $this->sql = null;
        $this->query_type = self::DROP;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "DROP " . ($is_tmp ? "TEMPORARY " : "") . "TABLE IF EXISTS `$schema`.`$table_name`";
        }

        return $this->execute(MYSQLI_BOTH);
    }

    /**
     * Function to build a truncate table statement (automatically executes)
     *
     * @param string $table_name
     *            Table to truncate
     *
     * @return string|NULL
     */
    public function truncate($table_name)
    {
        $this->sql = null;
        $this->query_type = self::TRUNCATE;

        if (! is_null($table_name) && is_string($table_name)) {
            $this->sql = "TRUNCATE TABLE $table_name";
        }

        return $this->execute(MYSQLI_BOTH);
    }

    /**
     * Function to build a create temporary table statement
     *
     * @param string $table_name
     *            Name to give the table when creating
     * @param boolean $is_tmp
     *            [optional]
     *            Optional boolean to make the table a temporary table
     * @param mixed $select
     *            [optional]
     *            Optional parameter if null uses last built statement
     *            If string, will be made the SQL statement executed to create the table
     *            If array, 2-dimensional array with "field", "datatype" values to build table fields
     *
     * @return NULL|string
     */
    public function create_table($table_name, $is_tmp = false, $select = null)
    {
        $this->query_type = self::CREATE_TABLE;

        if (is_null($select) && ! is_null($this->sql) && substr($this->sql, 0, 6) == 'SELECT') {
            $this->sql = "CREATE " . ($is_tmp ? "TEMPORARY" : "") . " TABLE IF NOT EXISTS $table_name AS ($this->sql)";
        }
        if (! is_null($table_name) && is_string($table_name) && is_string($select)) {
            $this->sql = "CREATE " . ($is_tmp ? "TEMPORARY" : "") . " TABLE IF NOT EXISTS $table_name AS ($select)";
        } elseif (! is_null($table_name) && is_string($table_name) && is_array($select)) {
            $this->sql = "CREATE " . ($is_tmp ? "TEMPORARY" : "") . " TABLE IF NOT EXISTS $table_name (";
            foreach ($select as $field) {
                $this->sql .= "{$field['field']} {$field['datatype']}" . (isset($field['default']) ? " {$field['default']}" : '') . (isset($field['option']) ? " {$field['option']}" : '') . ",";
            }
            $this->sql = substr($this->sql, 0, - 1) . ")";
        }

        if (AUTORUN) {
            return $this->execute();
        }

        return $this->sql;
    }

    /**
     * Function to create a table using a stdClass object derived from JSON
     *
     * @param stdClass $json
     */
    public function create_table_json($json)
    {
        $this->query_type = self::CREATE_TABLE;
        $this->c->select_db($json->schema);

        $this->sql = "CREATE TABLE IF NOT EXISTS `{$json->name}` (";
        foreach ($json->fields as $field) {
            $this->sql .= "`{$field->name}` {$field->dataType}";

            if ($field->dataType == 'enum') {
                $this->sql .= "('" . implode("','", $field->values) . "')";
            }

            if ($field->ai) {
                $this->sql .= " AUTO_INCREMENT";
            }

            if ($field->nn) {
                $this->sql .= " NOT NULL";
            } else {
                if ($field->default === null) {
                    $this->sql .= " DEFAULT NULL";
                } elseif (strlen($field->default)) {
                    $this->sql .= " DEFAULT '{$field->default}'";
                }
            }

            if ($field != end($json->fields)) {
                $this->sql .= ",";
            }
        }

        if (isset($json->index) && is_array($json->index) && count($json->index)) {
            foreach ($json->index as $ind) {
                $this->sql .= ", " . strtoupper($ind->type) . " `{$ind->id}` (`{$ind->ref}`)";
            }
        }

        if (isset($json->constraints) && is_array($json->constraints) && count($json->constraints)) {
            foreach ($json->constraints as $con) {
                $this->sql .= ", CONSTRAINT `{$con->id}` " . "FOREIGN KEY (`{$con->local}`) " . "REFERENCES `{$con->schema}`.`{$con->table}` (`{$con->field}`) " . "ON DELETE " . (is_null($con->delete) ? "NO ACTION" : strtoupper($con->delete)) . " " . "ON UPDATE " . (is_null($con->update) ? "NO ACTION" : strtoupper($con->update));
            }
        }

        if (isset($json->unique) && is_array($json->unique) && count($json->unique)) {
            $this->sql .= ", UNIQUE(`" . implode("`,`", $json->unique) . "`)";
        }

        if (isset($json->primary_key) && is_array($json->primary_key) && count($json->primary_key)) {
            $this->sql .= ", PRIMARY KEY(`" . implode("`,`", $json->primary_key) . "`))";
        } else {
            $this->sql = substr($this->sql, 0, - 1) . ")";
        }

        $this->execute();
    }

    /**
     * Function to alter a existing table
     *
     * @param string $table_name
     *            Table to alter
     * @param string $action
     *            What action should be taken ('add-column', 'drop-column', 'modify-column')
     * @param array $params
     *            [optional]
     *            Optional 2-dimensional array of parameters to act on. $action will dictate what parameters need to be present
     *
     * @return mixed
     */
    public function alter_table($table_name, $action, $params)
    {
        $this->query_type = self::ALTER_TABLE;
        $this->sql = "ALTER TABLE $table_name ";
        if ($action == 'add-column') {
            $nn = ($params->nn ? " NOT NULL" : "");
            $default = null;
            if ($params->default === null) {
                $default = " DEFAULT NULL";
            } elseif (strlen($params->default)) {
                $default = " DEFAULT '{$params->default}'";
            }
            $this->sql .= "ADD COLUMN {$params->name} {$params->dataType}" . $nn . $default;
        } elseif ($action == 'drop-column') {
            $this->sql .= "DROP COLUMN ";
            foreach ($params as $col) {
                $this->sql .= "{$col['name']},";
            }
            $this->sql = substr($this->sql, 0, - 1);
        } elseif ($action == 'modify-column') {}

        $this->debug(E_DEBUG);

        return $this->execute();
    }

    /**
     * Check to see if a field in a table exists
     *
     * @param string $schema
     *            Schema that contains tables
     * @param string $table_name
     *            Table to check
     * @param string $field_name
     *            Field name to find
     *
     * @return boolean Returns TRUE if field is found in that schema and table, otherwise FALSE
     */
    public function field_exists($schema, $table_name, $field_name)
    {
        $this->c->select_db($schema);

        $fdata = $this->field_data($schema, $table_name);

        foreach ($fdata as $field) {
            if ($field->name == $field_name) {
                return true;
            }
        }

        return false;
    }

    /**
     * Function to get the column data (datatype, flags, defaults, etc)
     *
     * @param string $schema
     *            Schema to search for table in
     * @param string $table_name
     *            Table to query
     * @param mixed $field
     *            [optional]
     *            Optional field to retrieve data (if null, returns data from all fields)
     *
     * @return array
     */
    public function field_data($schema, $table_name, $field = null)
    {
        $this->c->select_db($schema);

        if (is_null($field)) {
            $res = $this->c->query("SELECT * FROM $table_name LIMIT 1");
        } elseif (is_array($field)) {
            $res = $this->c->query("SELECT `" . implode("`,`", $field) . "` FROM $table_name LIMIT 1");
        } elseif (is_string($field)) {
            $res = $this->c->query("SELECT $field FROM $table_name LIMIT 1");
        } else {
            return null;
        }

        $fields = null;
        if (is_a($res, 'mysqli_result')) {
            $fields = $res->fetch_fields();
            foreach ($fields as $i => $f) {
                $fields["{$f->name}"] = $f;
                unset($fields[$i]);
            }
        }

        return $fields;
    }

    /**
     * Function to check that all field parameters are set correctly
     *
     * @param object $field_data
     * @param object $check
     * @param object $pks
     * @param object $index
     *
     * @return array
     */
    public function field_check($field_data, $check, $pks, $index)
    {
        $default = null;
        $ret = null;

        $nn = ($check->nn ? " NOT NULL" : null);
        if ($check->default === null) {
            $default = " DEFAULT NULL";
        } elseif (strlen($check->default)) {
            $default = " DEFAULT '{$check->default}'";
        }

        if ($field_data->type != $check->type && $check->type != MYSQLI_TYPE_ENUM) {
            $this->debug("{$field_data->name} wrong datatype, changing to {$check->dataType}");
            $ret = " CHANGE COLUMN `{$field_data->name}` `{$check->name}` {$check->dataType}" . "{$nn}{$default}";
        } elseif (! is_null($check->length) && $field_data->length != $check->length) {
            $this->debug("{$field_data->name} incorrect size ({$field_data->length} != {$check->length})");
            $ret = " CHANGE COLUMN `{$field_data->name}` `{$check->name}` {$check->dataType}" . "{$nn}{$default}";
        } elseif ($check->type == MYSQLI_TYPE_ENUM && ! ($field_data->flags & MYSQLI_ENUM_FLAG)) {
            $ret = " CHANGE COLUMN `{$field_data->name}` `{$check->name}` {$check->dataType}('" . implode("','", $check->values) . "')" . "{$nn}{$default}";
        }

        if (! is_null($index) && is_array($index) && count($index)) {
            foreach ($index as $ind) {
                if ($check->name == $ind->ref && ! ($field_data->flags & MYSQLI_MULTIPLE_KEY_FLAG)) {
                    $this->debug("{$field_data->name} is not an index");
                    $ret .= ($ret ? "," : "") . " ADD INDEX `{$ind->id}` (`{$ind->ref}` ASC)";
                }
            }
        }

        if (in_array($check->name, $pks) && ! ($field_data->flags & MYSQLI_PRI_KEY_FLAG)) {
            $ret .= ($ret ? "," : "") . " DROP PRIMARY KEY, ADD PRIMARY KEY(`" . implode("`,`", $pks) . "`)";
        }

        return $ret;
    }

    /**
     * Function to check for the existence of a table within a schema
     *
     * @param string $schema
     *            Schema to search for table
     * @param string $table_name
     *            Table to search for
     *
     * @return boolean Returns TRUE if table is found in that schema, otherwise FALSE
     */
    public function table_exists($schema, $table_name)
    {
        $this->c->select_db($schema);
        $res = $this->c->query("SHOW TABLES LIKE '$table_name'");
        if ($res->num_rows > 0) {
            return true;
        }

        return false;
    }

    /**
     * Function to detect if string is a JSON object or not
     *
     * @param string $val
     *
     * @return boolean
     */
    public function isJson($val)
    {
        json_decode($val);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    /**
     * Function to escape SQL characters to prevent SQL injection
     *
     * @param mixed $val
     *            Value to escape
     *
     * @return string Escaped value
     */
    public function _escape($val)
    {
        if (is_null($val)) {
            return 'NULL';
        } elseif (is_numeric($val) || is_string($val)) {
            if ($this->isJson($val)) {
                return "'{$this->c->real_escape_string($val)}'";
            } elseif (strtolower($val) == 'now()') {
                return $val;
            } elseif (preg_match("/\.`\w+`/", $val)) {
                return $val;
            }
            return "'{$this->c->real_escape_string($val)}'";
        } elseif (is_a($val, 'DateTime')) {
            return "'{$val->format(MYSQL_DT_FORMAT)}'";
        } elseif (is_bool($val)) {
            return $val ? "'1'" : "'0'";
        } elseif (gettype($val) == 'object') {
            $this->debug(E_ERROR, "Unknown object to escape " . get_class($val) . " in SQL string {$this->sql}");
        } else {
            $this->debug(E_ERROR, "Unknown datatype to escape in SQL string {$this->sql} " . gettype($val));
        }

        throw (new Exception("Unknown datatype to escape in SQL string {$this->sql} " . gettype($val), E_ERROR));
    }

    /**
     * Function to retrieve all results
     *
     * @param string $resulttype
     *
     * @return mixed
     */
    public function fetch_all($resulttype = MYSQLI_ASSOC)
    {
        $res = [];
        if (method_exists('mysqli_result', 'fetch_all')) { // Compatibility layer with PHP < 5.3
            $res = $this->result->fetch_all($resulttype);
        } else {
            while ($tmp = $this->result->fetch_array($resulttype)) {
                $res[] = $tmp;
            }
        }

        return $res;
    }

    /**
     * Function to debug the class
     *
     * @param int $errno
     * @param string $errmsg
     */
    public function debug($errno = E_NOTICE, $errmsg = null)
    {
        check_path(LOG_PATH . "/db.log");
        check_path(LOG_PATH . "/db.err");
        check_path(LOG_PATH . "/db.debug");

        $err_lvl = 'NOTICE';

        switch ($errno) {
            case E_DEBUG:
                $err_lvl = 'DEBUG';
                break;
            case E_WARNING:
                $err_lvl = 'WARNING';
                break;
            case E_ERROR:
                $err_lvl = 'FATAL ERROR';
                break;
        }

        $dt = new DateTime();

        if (is_null($errmsg)) {
            $errmsg = $this->sql;
        }

        file_put_contents(realpath(LOG_PATH . '/db.log'), "{$dt->format(DATE_ISO8601)}\t" . "$err_lvl\t" . "Executing: $this->query_type\t" . "SQL: {$errmsg}" . PHP_EOL, FILE_APPEND);

        if ($errno == E_DEBUG && $this->result && LOG_LEVEL == E_DEBUG && is_a($this->result, 'mysqli_result')) {
            file_put_contents(realpath(LOG_PATH . '/db.debug'), print_r($this->result, true), FILE_APPEND);
        } elseif ($errno == E_ERROR && $this->c->error) {
            file_put_contents(realpath(LOG_PATH . '/db.err'), "{$dt->format(DATE_ISO8601)}\t" . "{$this->c->error}" . PHP_EOL, FILE_APPEND);
            error_log($this->c->error);
            die($this->c->error);
        }
    }

    /**
     * Function to populate the fields for the SQL
     *
     * @param array $fields
     *            [optional]
     *            Optional array of fields to string together to create a field list
     *
     * @return string
     */
    public function fields($fields = null)
    {
        $str_fields = null;

        if (is_array($fields) && count($fields)) {
            foreach ($fields as $field) {
                if ((strpos($field, '`') === false) && (strpos($field, '.') === false) && (strpos($field, '*') === false) && (stripos($field, ' as ') === false)) {
                    $str_fields .= "`$field`,";
                } else {
                    $str_fields .= "$field,";
                }
            }
            $str_fields = substr($str_fields, 0, - 1);
        } elseif (is_null($fields)) {
            $str_fields = "*";
        }

        return $str_fields;
    }

    /**
     * Function to create the where statement for the SQL
     *
     * @param array $where
     *            Two-dimensional array to use to build the where clause
     *
     *            <code>
     *            array(<br />
     *            &nbsp;&nbsp;array(<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'field' => 'field_name',<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'op' => '=', // (common operations or IN, BETWEEN, LIKE, NOT_LIKE, IS, & IS_NOT constants)<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'value' => 'field_value',<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'sql_op' => 'AND', // NOT required for first element (common SQL operators AND, OR, NOR)<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'open-paren' => true, // optional to add a paren '(' BEFORE clause<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'close-paren' => true, // optional to add a paren ')' AFTER clause<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'low' => '1', // LOW value only used in BETWEEN clause<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'high' => '100', // HIGH value only used in BETWEEN clause<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;'case_insensitive' => true // optional boolean to set the parameters to LOWER to do case insenstive comparison
     *            &nbsp;&nbsp;),<br />
     *            &nbsp;&nbsp;array(<br />
     *            &nbsp;&nbsp;&nbsp;&nbsp;...<br />
     *            &nbsp;&nbsp;),<br />
     *            &nbsp;&nbsp;...<br />
     *            )
     *            </code>
     *
     * @return string
     */
    public function where($where)
    {
        $ret = " WHERE";

        foreach ($where as $x => $w) {
            if (! isset($w['field']) && isset($w['close-paren']) && $w['close-paren']) {
                $ret .= ")";
                continue;
            } elseif (! isset($w['field']) || ($x > 0 && ! isset($w['sql_op']))) {
                continue;
            }

            if ($x > 0) {
                $ret .= " {$w['sql_op']}";
            }

            if (isset($w['open-paren']) && $w['open-paren']) {
                $ret .= " (";
            }

            if ((strpos($w['field'], '`') === false) && (strpos($w['field'], '.') === false) && (strpos($w['field'], '*') === false) && (stripos($w['field'], ' as ') === false)) {
                $field = "`{$w['field']}`";
            } else {
                $field = $w['field'];
            }

            $not = null;
            if (isset($w['op']) && in_array($w['op'], array(
                IS_NOT,
                NOT_LIKE,
                NOT_IN
            ))) {
                $not = ' NOT';
            }

            if (isset($w['op']) && ($w['op'] == LIKE || $w['op'] == NOT_LIKE)) {
                $ret .= " {$field}{$not} LIKE {$w['value']}";
            } elseif (isset($w['op']) && ($w['op'] == IN || $w['op'] == NOT_IN) && is_string($w['value'])) {
                $ret .= " {$field}{$not} IN " . (strpos($w['value'], '(') !== false ? $w['value'] : "({$w['value']})");
            } elseif (isset($w['op']) && ($w['op'] == IN || $w['op'] == NOT_IN) && is_array($w['value'])) {
                $ret .= " {$field}{$not} IN (" . implode(",", array_map(array(
                    $this,
                    '_escape'
                ), $w['value'])) . ")";
            } elseif (isset($w['op']) && $w['op'] == BETWEEN) {
                if (! isset($w['low']) && ! isset($w['high'])) {
                    continue;
                }
                $ret .= " {$field} BETWEEN {$this->_escape($w['low'])} AND {$this->_escape($w['high'])}";
            } elseif (isset($w['op']) && ($w['op'] == IS || $w['op'] == IS_NOT)) {
                $ret .= " {$field} IS{$not} {$this->_escape($w['value'])}";
            } else {
                $op = "=";
                if (isset($w['op'])) {
                    $op = $w['op'];
                }
                if (isset($w['case_insensitive']) && $w['case_insensitive']) {
                    $ret .= " LOWER({$field}) {$op} LOWER({$this->_escape($w['value'])})";
                } elseif (preg_match("/\(SELECT/", $w['value'])) {
                    $ret .= " {$field} {$op} {$w['value']}";
                } else {
                    $ret .= " {$field} {$op} {$this->_escape($w['value'])}";
                }
            }

            if (isset($w['close-paren']) && $w['close-paren']) {
                $ret .= ")";
            }
        }
        if (strlen($ret) == 7) {
            $ret = '';
        }
        return $ret;
    }

    /**
     * Function to parse the flags
     *
     * @param array $flags
     *            Two-dimensional array to added flags
     *
     *            <code>
     *            array(
     *            &nbsp;&nbsp;'table_joins' => array(
     *            &nbsp;&nbsp;&nbsp;&nbsp;"JOIN table2 t2 ON t2.id=t1.id"
     *            &nbsp;&nbsp;),
     *            &nbsp;&nbsp;'group' => 'field',
     *            &nbsp;&nbsp;'having' => 'field',
     *            &nbsp;&nbsp;'order' => 'field',
     *            &nbsp;&nbsp;'start' => 0,
     *            &nbsp;&nbsp;'limit' => 0
     *            )
     *            </code>
     *
     * @see db_helper::groups()
     * @see db_helper::having()
     * @see db_helper::order()
     *
     * @return string
     */
    public function flags($flags)
    {
        $ret = '';

        if (isset($flags['group'])) {
            $ret .= $this->groups($flags['group']);
        }

        if (isset($flags['having']) && is_array($flags['having'])) {
            $ret .= $this->having($flags['having']);
        }

        if (isset($flags['order'])) {
            $ret .= $this->order($flags['order']);
        }

        if (isset($flags['limit']) && (is_string($flags['limit']) || is_numeric($flags['limit']))) {
            $ret .= " LIMIT ";
            if (isset($flags['start']) && (is_string($flags['start']) || is_numeric($flags['start']))) {
                $ret .= "{$flags['start']},";
            }
            $ret .= "{$flags['limit']}";
        }

        return $ret;
    }

    /**
     * Function to parse SQL GROUP BY statements
     *
     * @param mixed $groups
     *
     * @return string
     */
    private function groups($groups)
    {
        $ret = '';
        if (is_array($groups)) {
            $ret .= " GROUP BY";

            foreach ($groups as $grp) {
                $ret .= " $grp";
            }
        } elseif (is_string($groups)) {
            $ret .= " GROUP BY {$groups}";
        }

        return $ret;
    }

    /**
     * Function to parse SQL HAVING statements
     *
     * @param mixed $having
     *            return string
     */
    private function having($having)
    {
        $ret = " HAVING";
        $x = 0;
        foreach ($having as $h) {
            if (! isset($h['field']) || ($x > 0 && ! isset($h['sql_op']))) {
                continue;
            }

            if ($x > 0) {
                $ret .= " {$h['sql_op']} ";
            }

            if ($h['op'] == LIKE) {
                $ret .= " {$h['field']} LIKE {$h['value']}";
            } elseif ($h['op'] == IN && is_string($h['value'])) {
                $ret .= " {$h['field']} IN {$h['value']}";
            } elseif ($h['op'] == IN && is_array($h['value'])) {
                $ret .= " {$h['field']} IN ('" . implode("', '", $h['value']) . "')";
            } elseif ($h['op'] == BETWEEN) {
                $ret .= " {$h['field']} BETWEEN {$this->_escape($h['low'])} AND {$this->_escape($h['high'])}";
            } elseif ($h['op'] == IS) {
                $ret .= " {$h['field']} IS {$this->_escape($h['value'])}";
            } elseif ($h['op'] == IS_NOT) {
                $ret .= " {$h['field']} IS NOT {$this->_escape($h['value'])}";
            } else {
                $ret .= " {$h['field']} {$h['op']} {$this->_escape($h['value'])}";
            }

            $x ++;
        }

        return $ret;
    }

    /**
     * Function to parse SQL ORDER BY statements
     *
     * @param mixed $order
     *
     * @return string
     */
    private function order($order)
    {
        $ret = '';
        if (is_array($order)) {
            $ret .= " ORDER BY";

            foreach ($order as $ord) {
                $ret .= " {$ord['field']} {$ord['sort']},";
            }

            $ret = substr($ret, 0, - 1);
        } elseif (is_string($order)) {
            $ret .= " ORDER BY {$order}";
        }

        return $ret;
    }

    /**
     *
     * @return boolean
     */
    public static function run()
    {
        $args = func_get_args();
        $conn = null;

        if (is_array($args) && count($args) < 2) {
            return;
        }

        if (! is_a($args[0], "mysqli")) {
            return;
        } else {
            $conn = $args[0];
        }

        if (! is_string($args[1])) {
            return;
        } else {
            $sql = $args[1];
        }

        if (strpos($sql, "?") !== false) {
            $x = 2;
            while (strpos($sql, "?") !== false) {
                $sql = str_replace_first("?", "'" . $conn->real_escape_string($args[$x]) . "'", $sql);
            }
        }

        if (! $stmt = $conn->prepare($sql)) {
            print $conn->error . PHP_EOL;
            return;
        }

        if (! $stmt->execute()) {
            print "Execution of prepared statement failed: (" . $stmt->errno . ") " . $stmt->error . PHP_EOL;
            return false;
        }

        return true;
    }

    /**
     * Function
     *
     * @return void|mixed
     */
    public static function selectrow_array()
    {
        $args = func_get_args();
        $conn = null;
        $ret = [];

        if (is_array($args) && count($args) < 2) {
            return;
        }

        if (! is_a($args[0], "mysqli")) {
            return;
        } else {
            $conn = $args[0];
        }

        if (! is_string($args[1])) {
            return;
        } else {
            $sql = $args[1];
        }

        if (strpos($sql, "?") !== false) {
            $x = 2;
            while (strpos($sql, "?") !== false) {
                $sql = str_replace_first("?", "'" . $conn->real_escape_string($args[$x]) . "'", $sql);
            }
        }

        if (! $stmt = $conn->prepare($sql)) {
            print $conn->error . PHP_EOL;
            return;
        }

        if (! $stmt->execute()) {
            print "Execution of prepared statement failed: (" . $stmt->errno . ") " . $stmt->error . PHP_EOL;
            return;
        }

        $meta = $stmt->result_metadata();
        $fields = $fieldNames = [];

        while ($field = $meta->fetch_field()) {
            $fieldNames[] = $var = $field->name;
            $$var = null;
            $fields[$var] = &$$var;
        }

        $fieldCount = (is_array($fieldNames) ? count($fieldNames) : 0);

        call_user_func_array(array(
            $stmt,
            "bind_result"
        ), $fields);

        $i = 0;
        while ($stmt->fetch()) {
            for ($r = 0; $r < $fieldCount; $r ++) {
                $ret[$i][$fieldNames[$r]] = $fields[$fieldNames[$r]];
            }
        }

        if (is_array($ret) && count($ret) == 1) {
            return $ret[0];
        } else {
            return $ret;
        }
    }

    /**
     *
     * @return string
     */
    public static function mysql_escape_string()
    {
        $args = func_get_args();
        $conn = null;
        $sql = '';

        if (is_array($args) && count($args) < 3) {
            return;
        }

        if (! is_a($args[0], "mysqli")) {
            return;
        } else {
            $conn = $args[0];
        }

        if (! is_string($args[1])) {
            return;
        } else {
            $sql = $args[1];
        }

        if (strpos($sql, "?") !== false) {
            $x = 2;
            while (strpos($sql, "?") !== false) {
                $sql = str_replace_first("?", "'" . $conn->real_escape_string($args[$x]) . "'", $sql);
            }
        }

        return $sql;
    }

    public function is_constraint($con_id)
    {
        $res = $this->c->query("SELECT * FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_NAME = '$con_id'");

        if ($res->num_rows) {
            return true;
        }

        return false;
    }
}

/**
 * This file will contain all the variables and functions to operate a database
 * and for the ST&E Manager to interact with
 *
 * @author Ryan Prather
 */
class db
{

    /**
     * Array of words to be removed
     */
    private $DISALLOWED = array(
        'the',
        'be',
        'to',
        'of',
        'and',
        'a',
        'in',
        'that',
        'have',
        'I',
        'it',
        'for',
        'not',
        'on',
        'with',
        'he',
        'as',
        'you',
        'do',
        'at',
        'this',
        'but',
        'his',
        'by',
        'from',
        'they',
        'we',
        'say',
        'her',
        'she',
        'or',
        'an',
        'will',
        'my',
        'one',
        'all',
        'would',
        'there',
        'their',
        'what',
        'so',
        'up',
        'out',
        'if',
        'about',
        'who',
        'get',
        'which',
        'go',
        'me',
        'when',
        'make',
        'can',
        'like',
        'time',
        'no',
        'just',
        'him',
        'know',
        'take',
        'people',
        'into',
        'year',
        'your',
        'good',
        'some',
        'could',
        'them',
        'see',
        'other',
        'than',
        'then',
        'now',
        'look',
        'only',
        'come',
        'its',
        'over',
        'think',
        'also',
        'back',
        'after',
        'use',
        'two',
        'how',
        'our',
        'work',
        'first',
        'well',
        'way',
        'even',
        'new',
        'want',
        'because',
        'any',
        'these',
        'give',
        'day',
        'most',
        'us'
    );

    /**
     * The database connection
     *
     * @var mysqli
     * @access protected
     */
    protected $conn = null;

    /**
     * A private database helper
     *
     * @var db_helper
     * @access public
     */
    public $help = null;

    /**
     * Constant for the first column where target finding statuses start
     *
     * @var integer
     */
    const FIRST_ECHECKLIST_HOST_COL = 5;

    /**
     * Constructor function to instantiate a new DB object and connection
     *
     * @param bool $persistent
     *            [optional]
     */
    public function __construct($persistent = false)
    {
        // attempt to create a new database connection
        $host = ($persistent ? "p:" : "") . DB_SERVER;
        if (class_exists('mysqli')) {
            $pwd = self::decrypt_pwd();
            $this->conn = new mysqli($host, 'web', $pwd, 'sagacity');
        } else {
            die("Could not find the mysqli class");
        }
        // if there is a problem output that
        if ($this->conn->connect_errno && $this->conn->connect_errno == 1045) {
            die("Invalid database username and/or password");
        } elseif ($this->conn->connect_errno) {
            error_log("Error connecting to " . DB_SERVER . " " . $this->conn->connect_error);
            die("Error connecting to " . DB_SERVER);
        }

        // set the character set and default database
        $this->conn->set_charset("utf8");
        $this->conn->real_query("SET sql_mode=''");

        $this->help = new db_helper($this->conn);
    }

    /**
     * Function to decrypt the password
     *
     * @return string
     */
    public static function decrypt_pwd()
    {
        if (! file_exists(DOC_ROOT . "/" . PWD_FILE)) {
            die("Cannot connect to the database because the password file does not exist");
        }

        $enc_pwd = file_get_contents(DOC_ROOT . "/" . PWD_FILE);
        $pwd = my_decrypt($enc_pwd);

        return $pwd;
    }

    /**
     * Get the ID of the last command that was executed
     *
     * @return integer The integer of the last primary key id inserted into whatever table
     */
    public function get_Last_Insert_ID()
    {
        return $this->conn->insert_id;
    }

    // {{{ ADVISORY CLASS FUNCTIONS
    /**
     * Function to get an advisory from the database
     *
     * @param string $advisory_id
     *            [optional]
     *            String with advisory ID to specifically find
     *
     * @return array:advisory|NULL Returns array of advisory objects or NULL if nothing is found in the database
     */
    public function get_Advisory($advisory_id = null)
    {
        $ret = [];

        if (! is_null($advisory_id)) {
            $this->help->select("sagacity.advisories", null, array(
                array(
                    'field' => 'advisory_id',
                    'op' => '=',
                    'value' => $advisory_id
                )
            ));
        } else {
            $this->help->select("sagacity.advisories", null, []);
        }

        if ($ref = $this->help->execute()) {
            foreach ($ref as $row) {
                $ret[] = new advisory($row['pdi_id'], $row['advisory_id'], $row['reference'], $row['type'], $row['url']);
            }
            return $ret;
        } else {
            Sagacity_Error::sql_handler($this->help->sql);
            $this->help->debug(E_ERROR);
        }
        return null;
    }

    /**
     * Update or insert an advisory
     *
     * @param array:advisory $advisories
     *            Array of advisory class objects to save/update to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Advisory($advisories)
    {
        $values = [];
        $fields = [
            'pdi_id',
            'advisory_id',
            'type',
            'reference',
            'url',
            'title',
            'impact'
        ];
        foreach ($advisories as $adv) {
            $values[] = [
                $adv->get_PDI_ID(),
                $adv->get_Advisory_ID(),
                $adv->get_Type(),
                $adv->get_Ref_Text(),
                $adv->get_URL(),
                $adv->get_Title(),
                $adv->get_Impact()
            ];
        }

        $this->help->extended_replace("sagacity.advisories", $fields, $values);

        if (! $this->help->execute()) {
            Sagacity_Error::sql_handler($this->help->sql);
            $this->help->debug(E_ERROR);

            return false;
        }

        return true;
    }

    // }}}
    // {{{ CATEGORY CLASS FUNCTIONS
    /**
     * Get ST&E category data
     *
     * @param integer $int_Cat_ID
     *            [optional]
     *            Grab specific ste_cat from database (default NULL)
     *
     * @return array:ste_cat|NULL Returns an array of categories that are applicable to the specific ST&E or a specifically requested category
     */
    public function get_Category($int_Cat_ID = null)
    {
        $where = [];
        $ret = [];

        if ($int_Cat_ID != null) {
            $where[] = [
                'field' => 'id',
                'op' => '=',
                'value' => $int_Cat_ID
            ];
        }

        $this->help->select("ste_cat", null, $where);
        $cats = $this->help->execute();

        if (is_array($cats) && count($cats) && isset($cats['id'])) {
            $cats = [
                0 => $cats
            ];
        }

        if (is_array($cats) && count($cats)) {
            foreach ($cats as $cat) {
                $tmp = new ste_cat($cat['id'], $cat['ste_id'], $cat['name'], $cat['analysts']);

                $this->help->select("ste_cat_sources", [
                    'src_id'
                ], [
                    [
                        'field' => 'cat_id',
                        'op' => '=',
                        'value' => $cat['id']
                    ]
                ]);
                $srcs = $this->help->execute();
                if (is_array($srcs) && count($srcs) && isset($srcs['src_id'])) {
                    $srcs = [
                        0 => $srcs
                    ];
                }

                if (is_array($srcs) && count($srcs)) {
                    foreach ($srcs as $src) {
                        $tmp->add_Source($this->get_Sources($src['src_id']));
                    }
                }

                $this->get_Cat_Count($tmp);

                $ret[] = $tmp;
            }
        }

        return $ret;
    }

    /**
     * Function to automatically put targets in categories by operating systems<br />
     * Skips generic OS's and targets that already assigned
     *
     * @param int $ste_id
     */
    public function auto_Catorgize_Targets($ste_id)
    {
        $this->help->select("sagacity.target t", [
            't.id',
            't.os_string'
        ], [
            [
                'field' => 't.ste_id',
                'value' => $ste_id
            ],
            [
                'field' => 't.cat_id',
                'op' => IS,
                'value' => null,
                'sql_op' => 'AND'
            ],
            [
                'field' => 's.cpe',
                'op' => '!=',
                'value' => 'cpe:/o:generic:generic:-',
                'sql_op' => 'AND'
            ]
        ], [
            'table_joins' => [
                'JOIN sagacity.software s ON t.os_id=s.id'
            ]
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $id = 0;
                $this->help->select("sagacity.ste_cat", [
                    'id'
                ], [
                    [
                        'field' => 'ste_id',
                        'value' => $ste_id
                    ],
                    [
                        'field' => 'name',
                        'value' => trim($row['os_string']),
                        'sql_op' => 'AND'
                    ]
                ]);

                $tmp = $this->help->execute();
                if (is_array($tmp) && count($tmp) && isset($tmp['id'])) {
                    $id = $tmp['id'];
                } else {
                    $this->help->insert("sagacity.ste_cat", [
                        'ste_id' => $ste_id,
                        'name' => trim($row['os_string'])
                    ], true);
                    $id = $this->help->execute();
                }

                if ($id) {
                    $this->help->update("sagacity.target", [
                        'cat_id' => $id
                    ], [
                        [
                            'field' => 'id',
                            'value' => $row['id']
                        ]
                    ]);
                    $this->help->execute();
                }
            }
        }
    }

    /**
     * Function to save categories
     *
     * @param ste_cat $ste_cat_in
     *
     * @return mixed Returns FALSE if failed, otherwise the ID of the newly inserted category
     */
    public function save_Category($ste_cat_in)
    {
        if (is_null($ste_cat_in->get_ID())) {
            $this->help->insert("sagacity.ste_cat", array(
                'ste_id' => $ste_cat_in->get_STE_ID(),
                'name' => $ste_cat_in->get_Name(),
                'analysts' => $ste_cat_in->get_Analyst()
            ));

            if (! ($cat_id = $this->help->execute())) {
                $this->help->debug(E_ERROR);
                return false;
            }

            $ste_cat_in->set_ID($cat_id);
        } else {
            $this->help->update("sagacity.ste_cat", array(
                'name' => $ste_cat_in->get_Name(),
                'analysts' => $ste_cat_in->get_Analyst()
            ), array(
                array(
                    'field' => 'id',
                    'op' => '=',
                    'value' => $ste_cat_in->get_ID()
                )
            ));

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }
        }

        if (is_array($ste_cat_in->get_Sources()) && count($ste_cat_in->get_Sources())) {
            $this->help->delete("ste_cat_sources", null, [
                [
                    'field' => 'cat_id',
                    'op' => '=',
                    'value' => $ste_cat_in->get_ID()
                ]
            ]);
            $this->help->execute();

            $srcs = [];
            foreach ($ste_cat_in->get_Sources() as $src) {
                $srcs[] = [
                    $ste_cat_in->get_ID(),
                    $src->get_ID()
                ];
            }
            $this->help->extended_insert("ste_cat_sources", [
                'cat_id',
                'src_id'
            ], $srcs);
            $this->help->execute();
        }

        return $ste_cat_in->get_ID();
    }

    /**
     * This function renames a category
     *
     * @param integer $intOldCat
     *            Category ID of the category to rename
     * @param string $strNewCatName
     *            New name for the category
     *
     * @return boolean Return TRUE if successful, otherwise FALSE
     */
    public function rename_Cat($intOldCat, $strNewCatName)
    {
        $this->help->update("sagacity.ste_cat", array(
            'name' => $strNewCatName
        ), array(
            array(
                'field' => 'id',
                'op' => '=',
                'value' => $intOldCat
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * This function deletes a category and assigns the targets to "Unassigned"
     *
     * @param integer $intCat
     *            ID of the category to delete
     *
     * @return boolean Return TRUE if successful, otherwise FALSE
     */
    public function delete_Cat($intCat)
    {
        $this->help->update("sagacity.target", array(
            'cat_id' => null
        ), array(
            array(
                'field' => 'cat_id',
                'op' => '=',
                'value' => $intCat
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $this->help->delete("sagacity.ste_cat_sources", null, array(
            array(
                'field' => 'cat_id',
                'op' => '=',
                'value' => $intCat
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $this->help->delete("sagacity.category_interview", null, array(
            array(
                'field' => 'cat_id',
                'op' => '=',
                'value' => $intCat
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $this->help->delete("sagacity.ste_cat", null, array(
            array(
                'field' => 'id',
                'op' => '=',
                'value' => $intCat
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * This function sets the analyst that is in charge of this category
     *
     * @param integer $intCat
     *            Category ID to update
     * @param string $strAnalyst
     *            Name of the analyst
     *
     * @return boolean Return TRUE if successful, otherwise FALSE
     */
    public function assign_Analyst_To_Category($intCat, $strAnalyst)
    {
        $analysts = strtolower($strAnalyst) == 'none' ? null : $strAnalyst;
        $this->help->update("sagacity.ste_cat", array(
            'analysts' => $analysts
        ), array(
            array(
                'field' => 'id',
                'op' => '=',
                'value' => $intCat
            )
        ));
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * This function does the move of a tgt to a new category
     *
     * @param array:integer $arrTgts
     *            Array of integer ID for each target to move
     * @param integer $intCat
     *            Category ID to reassign them to
     *
     * @return boolean Return TRUE if successful, otherwise FALSE
     */
    public function move_Tgt_To_Cat($arrTgts, $intCat)
    {
        $this->help->update("sagacity.target", array(
            'cat_id' => $intCat
        ), array(
            array(
                'field' => 'id',
                'op' => IN,
                'value' => $arrTgts
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ CCE CLASS FUNCTIONS
    /**
     * Getter function for CCE
     *
     * @param string $cce_id
     *            CCE ID to query for
     *
     * @return array:cce
     */
    public function get_CCE($cce_id = null)
    {
        $ret = [];
        $where = [];

        if (! is_null($cce_id)) {
            $where[] = array(
                'field' => 'cce_id',
                'op' => '=',
                'value' => $cce_id
            );
        }

        $this->help->select("sagacity.cce", array(
            'pdi_id',
            'cce_id'
        ), $where);

        $cces = $this->help->execute();
        if (is_array($cces) && count($cces) && isset($cces['pdi_id'])) {
            $cces = array(
                0 => $cces
            );
        }

        if (is_array($cces) && count($cces) && isset($cces[0])) {
            foreach ($cces as $cce) {
                $ret[] = new cce($cce['pdi_id'], $cce['cce_id']);
            }
        }

        return $ret;
    }

    /**
     * Function to save CCE's to database
     *
     * @param array:cce|cce $cces
     *            An array of CCE's that need to be saved
     *
     * @return boolean Returns TRUE if save was successful, otherwise FALSE
     */
    public function save_CCE($cces)
    {
        $ret = true;
        $fields = array(
            'pdi_id',
            'cce_id'
        );
        $params = [];

        if (is_array($cces)) {
            foreach ($cces as $cce) {
                $params[] = [
                    $cce->get_PDI_ID(),
                    $cce->get_CCE_ID()
                ];
            }

            $this->help->extended_replace("sagacity.cce", $fields, $params);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                $ret = false;
            }
        } else {
            $this->help->replace("sagacity.cce", array(
                'pdi_id' => $cces->get_PDI_ID(),
                'cce_id' => $cces->get_CCE_ID()
            ));

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                $ret = false;
            }
        }

        return $ret;
    }

    // }}}
    // {{{ CCI CLASS FUNCTIONS
    public function get_CCI($cci_id = null)
    {
        $ret = [];

        $this->help->select("sagacity.cci");

        if (! is_null($cci_id)) {
            $this->help->select("sagacity.cci", null, array(
                array(
                    'field' => 'cci_id',
                    'op' => '=',
                    'value' => $cci_id
                )
            ));
        }

        $ccis = $this->help->execute();

        if (is_array($ccis) && count($ccis)) {
            foreach ($ccis as $cci_data) {
                $cci = new cci();
                $cci->cci_id = $cci_data['cci_id'];
                $cci->definition = $cci_data['definition'];
                $cci->type = $cci_data['type'];
                $cci->param = $cci_data['param'];
                $cci->note = $cci_data['note'];

                $this->help->select("sagacity.cci_refs", null, array(
                    array(
                        'field' => 'cci_id',
                        'op' => '=',
                        'value' => $cci_data['cci_id']
                    )
                ));
                $refs = $this->help->execute();
                if (is_array($refs) && count($refs)) {
                    foreach ($refs as $ref_data) {
                        $ref = new cci_reference();
                        $ref->index = $ref_data['index'];
                        $ref->url = $ref_data['url'];
                        $ref->title = $ref_data['title'];
                        $ref->ver = $ref_data['ver'];

                        $cci->refs[] = $ref;
                    }
                }

                $ret[] = $cci;
            }
        } else {
            $this->help->debug(E_ERROR);
        }

        return $ret;
    }

    /**
     * Get eMASS CCI Map
     *
     * @author Matt Shuter
     *
     * @return array Array of CCI-eMASS control mappings
     */
    public function get_EMASS_CCIs()
    {
        $this->help->select("rmf.emass_cci");
        $ret = $this->help->execute();
        return $ret;
    }

    /**
     * Function to save a CCI
     *
     * @param array:cci|cci $cci_in
     *
     * @return boolean
     */
    public function save_CCI($cci_in)
    {
        if (is_array($cci_in)) {
            $ccis = [];
            foreach ($cci_in as $cci) {
                $cci_id = preg_replace("/CCI\-[0]+/", "CCI-", $cci->cci_id);
                $ccis[] = [
                    $cci_id,
                    $cci->control_id,
                    $cci->enh_id,
                    $cci->definition,
                    $cci->guidance,
                    $cci->procedure
                ];
            }
            $this->help->extended_insert('rmf.cci', array(
                'id',
                'control_id',
                'enh_id',
                'def',
                'guidance',
                'procedure'
            ), $ccis, true);
        } else {
            $cci_id = preg_replace("/CCI\-[0]+/", "CCI-", $cci_in->cci_id);
            $this->help->insert('rmf.cci', array(
                'cci_id' => $cci_id,
                'control_id' => $cci_in->control_id,
                'enh_id' => $cci_in->enh_id,
                'def' => $cci_in->definition,
                'guidance' => $cci_in->guidance,
                'procedure' => $cci_in->procedure
            ), true);
        }

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to save an array of eMASS-CCI mappings
     *
     * @param array:cci $cci_in
     *
     * @return boolean
     */
    public function save_EMASS_CCIs($ccis_in)
    {
        $ret = false;
        $columns = array(
            'id',
            'control'
        );
        $this->help->extended_insert('rmf.emass_cci', $columns, $ccis_in, true);

        if ($this->help->execute()) {
            $ret = true;
        } else {
            $this->help->debug(E_ERROR);
        }

        return $ret;
    }

    // }}}
    // {{{ CHECKLIST CLASS FUNCTIONS
    /**
     * Get a checklist
     *
     * @param mixed $Checklist_ID
     *            [optional]
     *            Checklist ID to query for (default NULL)
     * @param boolean $ord_desc
     *            [optional]
     *            Decide if you want to order to return from newest release
     *
     * @return array:checklist Returns an array of checklists, or an empty array if none found
     */
    public function get_Checklist($Checklist_ID = null, $ord_desc = false)
    {
        $ret = [];

        if ($ord_desc) {
            $this->help->select("sagacity.checklist", [
                'id',
                'checklist_id',
                'name',
                'description',
                'date',
                'file_name',
                'ver',
                "MAX(LPAD(`release`, 0, 2)) AS 'release'",
                'type',
                'icon'
            ]);
        } else {
            $this->help->select("sagacity.checklist", null);
        }

        $where = [];
        if (! is_null($Checklist_ID)) {
            if (is_numeric($Checklist_ID)) {
                $where[] = [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $Checklist_ID
                ];
            } elseif (is_array($Checklist_ID)) {
                if (isset($Checklist_ID['checklist_id'])) {
                    $where[] = [
                        'field' => 'checklist_id',
                        'op' => '=',
                        'value' => $Checklist_ID['checklist_id']
                    ];
                }

                if (isset($Checklist_ID['type'])) {
                    $where[] = [
                        'field' => 'type',
                        'op' => '=',
                        'value' => $Checklist_ID['type'],
                        'sql_op' => 'AND'
                    ];
                }

                if (isset($Checklist_ID['version'])) {
                    $where[] = [
                        'field' => 'ver',
                        'op' => '=',
                        'value' => $Checklist_ID['version'],
                        'sql_op' => 'AND'
                    ];
                }

                if (isset($Checklist_ID['release'])) {
                    $where[] = [
                        'field' => 'release',
                        'op' => '=',
                        'value' => $Checklist_ID['release'],
                        'sql_op' => 'AND'
                    ];
                }
            } else {
                $where[] = [
                    'field' => 'checklist_id',
                    'op' => '=',
                    'value' => $Checklist_ID
                ];
            }
        }

        if (is_array($where) && count($where)) {
            $this->help->sql .= $this->help->where($where);
        }

        $flags = [];
        if ($ord_desc) {
            $flags = [
                'group' => 'type',
                'order' => [
                    [
                        'field' => 'name',
                        'sort' => 'asc'
                    ],
                    [
                        'field' => 'type',
                        'sort' => 'asc'
                    ],
                    [
                        'field' => 'ver',
                        'sort' => 'desc'
                    ],
                    [
                        'field' => 'LPAD(`release`,2,0)',
                        'sort' => 'desc'
                    ]
                ]
            ];
        } else {
            $flags = [
                'order' => [
                    [
                        'field' => 'name',
                        'sort' => 'asc'
                    ],
                    [
                        'field' => 'type',
                        'sort' => 'asc'
                    ],
                    [
                        'field' => 'ver',
                        'sort' => 'asc'
                    ],
                    [
                        'field' => 'LPAD(`release`,2,0)',
                        'sort' => 'asc'
                    ]
                ]
            ];
        }

        if (is_array($flags) && count($flags)) {
            $this->help->sql .= $this->help->flags($flags);
        }

        $rows = $this->help->execute();
        if (isset($rows['id'])) {
            $rows = array(
                0 => $rows
            );
        }

        if (is_array($rows) && count($rows)) {
            foreach ($rows as $row) {
                $chk = new checklist($row['id'], $row['checklist_id'], $row['name'], $row['description'], $row['date'], $row['file_name'], $row['ver'], $row['release'], $row['type'], $row['icon']);
                /*
                 * $this->help->select("sagacity.checklist_software_lookup", array('sw_id'), array(
                 * array(
                 * 'field' => 'chk_id',
                 * 'op' => '=',
                 * 'value' => $row['id']
                 * )
                 * ));
                 * $sw_rows = $this->help->execute();
                 * if (count($sw_rows)) {
                 * if (isset($sw_rows['sw_id'])) {
                 * $sw_rows = array(0 => $sw_rows);
                 * }
                 *
                 * foreach ($sw_rows as $row2) {
                 * $chk->add_SW($this->get_Software($row2['sw_id']));
                 * }
                 * }
                 */
                $ret[] = $chk;
            }
        }

        return $ret;
    }
    
    /**
     * Function to get the checklists by the checklist name in an eChecklist file
     * 
     * @param array:string $chk_arr
     * 
     * @return array:checklist
     */
    public function get_Checklist_By_Name($chk_arr)
    {
        $ret = [];
        $this->help->select("checklist", null, [
            [
                'field' => "CONCAT(`name`, ' V', `ver`, 'R', `release`, ' (', `type`, ')')",
                'op' => IN,
                'value' => $chk_arr,
                'backticks' => false
            ]
        ]);
        $rows = $this->help->execute();
        if(is_array($rows) && count($rows) && isset($rows[0])) {
            foreach($rows as $row) {
                $ret[] = new checklist($row['id'], $row['checklist_id'], $row['name'], $row['description'], new DateTime($row['date']), $row['file_name'], $row['ver'], $row['release'], $row['type'], $row['icon']);
            }
        } elseif(is_array($rows) && count($rows) && isset($rows['id'])) {
            $ret = new checklist($rows['id'], $rows['checklist_id'], $rows['name'], $rows['description'], new DateTime($rows['date']), $rows['file_name'], $rows['ver'], $rows['release'], $rows['type'], $rows['icon']);
        }
        
        return $ret;
    }

    /**
     * Function to get the checklist based on the checklist filename
     *
     * @param string $fname
     *
     * @return mixed
     */
    public function get_Checklist_By_File($fname)
    {
        $ret = [];
        $this->help->select("sagacity.checklist", null, [
            [
                'field' => 'file_name',
                'value' => $fname
            ]
        ]);

        $rows = $this->help->execute();
        if (isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $chk = new checklist($row['id'], $row['checklist_id'], $row['name'], $row['description'], $row['date'], $row['file_name'], $row['ver'], $row['release'], $row['type'], $row['icon']);
                /* */
                $this->help->select("sagacity.checklist_software_lookup", [
                    'sw_id'
                ], [
                    [
                        'field' => 'chk_id',
                        'value' => $row['id']
                    ]
                ]);
                $sw_rows = $this->help->execute();
                if (is_array($sw_rows) && count($sw_rows)) {
                    if (isset($sw_rows['sw_id'])) {
                        $sw_rows = [
                            0 => $sw_rows
                        ];
                    }

                    foreach ($sw_rows as $row2) {
                        $chk->add_SW($this->get_Software($row2['sw_id']));
                    }
                }

                $ret[] = $chk;
            }
        }

        return $ret;
    }

    /**
     * Function to retrieve the most current checklist for a given software package
     *
     * @param software $software
     *            Software of which to look for checklists
     *
     * @return array:checklist Returns an array of checklists that this software ties to. Otherwise, an empty array
     */
    public function get_Latest_Checklist_By_Software($software)
    {
        $ret = [];
        $this->help->create_table("c", true, $this->help->select("sagacity.checklist", null, [], array(
            'order' => '`ver` DESC, CONVERT(`release`, DECIMAL(4,2)) DESC'
        )));
        if (! $this->help->execute()) {
            return $ret;
        }

        $this->help->select("c", array(
            'c.id'
        ), array(
            array(
                'field' => 'csl.sw_id',
                'op' => '=',
                'value' => $software->get_ID()
            )
        ), array(
            'table_joins' => array(
                "JOIN sagacity.checklist_software_lookup csl ON csl.chk_id=c.id"
            ),
            'group' => 'c.name,c.type',
            'order' => 'c.name'
        ));

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = array(
                0 => $rows
            );
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $chk = $this->get_Checklist($row['id']);
                if (is_array($chk) && count($chk) && isset($chk[0])) {
                    $ret[] = $chk[0];
                }
            }
        }

        return $ret;
    }

    /**
     * Get a summary of checklist stats
     *
     * @param integer $cat_id
     *            Integer category ID to get the summary on
     *
     * @return NULL|array:targets,checklist,string Returns an associative array of target (id & name), checklists, and a summary that joins the two
     */
    public function get_Checklist_Summary($cat_id)
    {
        $where = array(
            array(
                'field' => 't.cat_id',
                'op' => (is_null($cat_id) ? IS : '='),
                'value' => $cat_id
            )
        );
        $tgts = [];
        $chklsts = [];
        $summary = [];

        $this->help->select("sagacity.target_checklist tc", null, $where, array(
            'table_joins' => array(
                "LEFT JOIN sagacity.target t ON t.id=tc.tgt_id"
            ),
            'group' => 't.id'
        ));

        $tgt_rows = $this->help->execute();
        if (is_array($tgt_rows) && count($tgt_rows) && isset($tgt_rows['name'])) {
            $tgt_rows = array(
                0 => $tgt_rows
            );
        }

        if (is_array($tgt_rows) && count($tgt_rows) && isset($tgt_rows[0])) {
            foreach ($tgt_rows as $row) {
                $tgts[$row['id']] = $row['name'];
            }
        } else {
            $this->help->debug(E_ERROR);
        }

        $this->help->select("sagacity.target_checklist tc", array(
            'c.id',
            'c.name',
            'c.type',
            'c.ver',
            'c.`release`'
        ), $where, array(
            'table_joins' => array(
                "LEFT JOIN sagacity.checklist c ON tc.chk_id=c.id",
                "LEFT JOIN sagacity.target t ON tc.tgt_id=t.id"
            ),
            'group' => 'c.id',
            'order' => 'c.name'
        ));

        $chk_rows = $this->help->execute();
        if (is_array($chk_rows) && count($chk_rows) && isset($chk_rows['id'])) {
            $chk_rows = array(
                0 => $chk_rows
            );
        }

        if (is_array($chk_rows) && count($chk_rows) && isset($chk_rows[0])) {
            foreach ($chk_rows as $row) {
                $chklsts[$row['id']] = "{$row['name']} V{$row['ver']}R{$row['release']} (" . ($row['type'] == 'iavm' ? 'IAVM' : ucfirst($row['type'])) . ")";
            }
        } else {
            $this->help->debug(E_ERROR);
        }

        $this->help->select("sagacity.findings f", array(
            "COUNT(1) as 'cnt'",
            'c.id',
            'c.name',
            'c.ver',
            'c.`release`'
        ), array(
            array(
                'field' => 't.cat_id',
                'op' => (is_null($cat_id) ? IS : '='),
                'value' => $cat_id
            ),
            array(
                'field' => 'c.name',
                'op' => '=',
                'value' => 'Orphan',
                'sql_op' => 'AND'
            )
        ), array(
            'table_joins' => array(
                "LEFT JOIN sagacity.target t ON t.id=f.tgt_id",
                "LEFT JOIN sagacity.pdi_checklist_lookup pcl ON pcl.pdi_id=f.pdi_id",
                "LEFT JOIN sagacity.checklist c ON pcl.checklist_id=c.id"
            )
        ));
        $chk_rows2 = $this->help->execute();
        if (is_array($chk_rows2) && count($chk_rows2) && isset($chk_rows2['cnt'])) {
            if ($chk_rows2['cnt'] > 0) {
                $chklsts[$chk_rows2['id']] = "{$chk_rows2['name']} V{$chk_rows2['ver']}R{$chk_rows2['release']}";
            }
        }

        foreach ($chklsts as $chk_key => $chk) {
            foreach ($tgts as $host_key => $host) {
                if ($chk != 'Orphan') {
                    $this->help->select_count("sagacity.target_checklist tc", [
                        [
                            'field' => 'tc.tgt_id',
                            'op' => '=',
                            'value' => $host_key
                        ],
                        [
                            'field' => 'tc.chk_id',
                            'op' => '=',
                            'value' => $chk_key,
                            'sql_op' => 'AND'
                        ]
                    ]);
                } else {
                    $this->help->select("sagacity.findings f", [
                        "IF(COUNT(1) > 0, '1', '0')"
                    ], [
                        [
                            'field' => 'f.tgt_id',
                            'op' => '=',
                            'value' => $host_key
                        ],
                        [
                            'field' => 'c.name',
                            'op' => '=',
                            'value' => 'Orphan',
                            'sql_op' => 'AND'
                        ]
                    ], [
                        'table_joins' => [
                            "LEFT JOIN sagacity.pdi_checklist_lookup pcl ON pcl.pdi_id=f.pdi_id",
                            "LEFT JOIN sagacity.checklist c ON c.id=pcl.checklist_id"
                        ]
                    ]);
                }

                $summary[$chk_key][$host_key] = $this->help->execute();
            }
        }

        return [
            'tgts' => $tgts,
            'checklists' => $chklsts,
            'summary' => $summary
        ];
    }

    /**
     * Get all checklist & targets in a category
     *
     * @param integer $cat_id
     *            Category ID to pull the checklists from
     *
     * @return NULL|array:string checklist
     */
    public function get_Category_Checklists($cat_id)
    {
        $chklsts = [];

        $this->help->select("sagacity.target_checklist tc", array(
            'tc.tgt_id',
            'tc.chk_id'
        ), array(
            array(
                'field' => 't.cat_id',
                'op' => '=',
                'value' => $cat_id
            )
        ), array(
            'table_joins' => array(
                "LEFT JOIN sagacity.target t ON tc.tgt_id = t.id",
                "LEFT JOIN sagacity.checklist c ON tc.chk_id = c.id"
            ),
            'order' => 'c.name'
        ));

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['tgt_id'])) {
            $rows = array(
                0 => $rows
            );
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $chk = $this->get_Checklist($row['chk_id']);
                if (is_array($chk) && count($chk) && isset($chk[0]) && is_a($chk[0], 'checklist')) {
                    $chk = $chk[0];
                } else {
                    continue;
                }

                $tgts = isset($chklsts[$chk->get_ID()]['tgts']) ? $chklsts[$chk->get_ID()]['tgts'] : null;
                $chklsts[$chk->get_ID()] = array(
                    'tgts' => $tgts . $row['tgt_id'] . ",",
                    'checklist' => $chk
                );
            }
        }

        $this->help->select_count("sagacity.target t", array(
            array(
                'field' => 't.cat_id',
                'op' => '=',
                'value' => $cat_id
            ),
            array(
                'field' => 'pcl.checklist_id',
                'op' => '=',
                'value' => "(SELECT c.id FROM sagacity.checklist c WHERE c.name='Orphan')",
                'sql_op' => 'AND'
            )
        ), array(
            'table_joins' => array(
                "LEFT JOIN sagacity.findings f ON t.id=f.tgt_id",
                "LEFT JOIN sagacity.pdi_checklist_lookup pcl ON pcl.pdi_id=f.pdi_id"
            )
        ));

        $count = $this->help->execute();
        if ($count) {
            $this->help->select("sagacity.target t", array(
                "t.id AS 'tgt_id'",
                "pcl.checklist_id AS 'chk_id'"
            ), array(
                array(
                    'field' => 't.cat_id',
                    'op' => '=',
                    'value' => $cat_id
                ),
                array(
                    'field' => 'pcl.checklist_id',
                    'op' => '=',
                    'value' => "(SELECT c.id FROM sagacity.checklist c WHERE c.name='Orphan')",
                    'sql_op' => 'AND'
                )
            ), array(
                'table_joins' => array(
                    "LEFT JOIN sagacity.findings f ON t.id=f.tgt_id",
                    "LEFT JOIN sagacity.pdi_checklist_lookup pcl ON pcl.pdi_id=f.pdi_id"
                ),
                'group' => 't.id,pcl.checklist_id'
            ));

            $rows2 = $this->help->execute();
            if (is_array($rows2) && count($rows2) && isset($rows2['tgt_id'])) {
                $rows2 = array(
                    0 => $rows2
                );
            }

            if (is_array($rows2) && count($rows2) && isset($rows2[0])) {
                foreach ($rows2 as $row2) {
                    $chk = $this->get_Checklist($row2['chk_id']);
                    if (is_array($chk) && count($chk) && isset($chk[0]) && is_a($chk[0], 'checklist')) {
                        $chk = $chk[0];
                    } else {
                        continue;
                    }

                    $tgts = isset($chklsts[$chk->get_ID()]['tgts']) ? $chklsts[$chk->get_ID()]['tgts'] : "";
                    $chklsts[$chk->get_ID()] = array(
                        'tgts' => $tgts . $row2['tgt_id'] . ",",
                        'checklist' => $chk
                    );
                }
            }
        }

        return $chklsts;
    }

    /**
     * Get array of checklists for a target
     *
     * @param integer $tgt_id
     *            The target ID of the target we want checklists from
     *
     * @return array:checklist |NULL
     *         Returns an array of checklists that are assigned to the requested target
     */
    public function get_Target_Checklists($tgt_id)
    {
        $this->help->select("sagacity.target_checklist tc", [
            'c.id',
            'tc.class'
        ], [
            [
                'field' => 'tc.tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN sagacity.checklist c ON c.id=tc.chk_id"
            ],
            'order' => 'c.name'
        ]);
        $chk = [];
        $chks = $this->help->execute();

        if (isset($chks['id'])) {
            $chks = [
                0 => $chks
            ];
        }

        if (is_array($chks) && count($chks) && isset($chks[0])) {
            foreach ($chks as $row) {
                /** @var checklist $checklist */
                $checklist = $this->get_Checklist($row['id'])[0];
                $checklist->set_Classification($row['class']);

                $chk[$checklist->get_ID()] = $checklist;
            }
        }

        // get the orphan checklist ID
        $this->help->select("sagacity.checklist", [
            'id'
        ], [
            [
                'field' => 'name',
                'op' => '=',
                'value' => 'Orphan'
            ]
        ]);
        $orphan = $this->help->execute();

        // check to see if this target has findings from the Orphan checklist
        $this->help->select_count("sagacity.pdi_checklist_lookup pcl", [
            [
                'field' => 'pcl.checklist_id',
                'op' => '=',
                'value' => $orphan['id']
            ],
            [
                'field' => 'f.tgt_id',
                'op' => '=',
                'value' => $tgt_id,
                'sql_op' => 'AND'
            ]
        ], [
            'table_joins' => [
                "RIGHT JOIN sagacity.findings f ON pcl.pdi_id=f.pdi_id"
            ]
        ]);
        $cnt = $this->help->execute();

        // add the orphan checklist if findings exist
        if ($cnt) {
            $chk[] = $this->get_Checklist($orphan['id'])[0];
        }

        return $chk;
    }

    /**
     * Function for getting eChecklist data to export
     *
     * @param int $cat_id
     * @param array $chk_host_list
     * @param string $status
     * @param int $category
     *
     * @return array
     */
    public function get_Category_Findings($cat_id, $chk_host_list = [], $status = null, $category = null)
    {
        $ret = [];
        $stigs = [];
        $tgt_ids = [];

        $where = [
            [
                'field' => 'gcf.cat_id',
                'op' => (is_null($cat_id) ? IS : '='),
                'value' => $cat_id
            ]
        ];

        if (! is_null($status)) {
            $where[] = [
                'field' => 'gcf.status',
                'op' => '=',
                'value' => $status,
                'sql_op' => 'AND',
                'open-paren' => true
            ];

            if ($status == 'Not Reviewed') {
                $where[] = [
                    'field' => 'gcf.status',
                    'op' => IS,
                    'value' => null,
                    'sql_op' => 'OR',
                    'close-paren' => true
                ];
            } else {
                unset($where[1]['open-paren']);
            }
        }

        if (! is_null($category)) {
            $where[] = [
                'field' => 'gcf.cat',
                'op' => '=',
                'value' => $category,
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("sagacity.get_cat_findings gcf", null, $where);
        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['tgt_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                if (is_null($row['chk_icon']) || $row['chk_icon'] == '') {
                    $worksheet_name = '(Unknown)';
                } else {
                    $worksheet_name = substr($row['chk_icon'], 0, - 4);
                }

                if (! isset($ret[$worksheet_name])) {
                    $ret[$worksheet_name] = [
                        'target_list' => [],
                        'checklists' => [],
                        'stigs' => []
                    ];
                    $where2 = [
                        [
                            'field' => 't.cat_id',
                            'op' => '=',
                            'value' => $cat_id
                        ],
                        [
                            'field' => 'c.icon',
                            'op' => LIKE,
                            'value' => "'$worksheet_name%'",
                            'sql_op' => 'AND'
                        ]
                    ];

                    if (is_array($tgt_ids) && count($tgt_ids)) {
                        $where2[] = [
                            'field' => 't.id',
                            'op' => IN,
                            'value' => $tgt_ids,
                            'sql_op' => 'AND'
                        ];
                    }

                    $this->help->select("target t", [
                        't.class'
                    ], $where2, [
                        'table_joins' => [
                            "LEFT JOIN target_checklist tc ON tc.tgt_id = t.id",
                            "LEFT JOIN checklist c ON c.id=tc.chk_id"
                        ],
                        'group' => 't.class',
                        'order' => "FIELD(t.class, 'S', 'FOUO', 'U')"
                    ]);
                    $rows2 = $this->help->execute();
                    if (is_array($rows2) && count($rows2) && isset($rows2['class'])) {
                        $ret[$worksheet_name]['highest_class'] = $rows2['class'];
                    }
                }

                if (! in_array($row['chk_id'], $ret[$worksheet_name]['checklists'])) {
                    $ret[$worksheet_name]['checklists'][] = $row['chk_id'];
                }

                if (! isset($ret[$worksheet_name]['target_list'][$row['tgt_name']])) {
                    $ret[$worksheet_name]['target_list']["{$row['tgt_name']}"] = count($ret[$worksheet_name]['target_list']) + 6;
                }

                if (! isset($ret[$worksheet_name]['stigs'][$row['stig_id']])) {
                    if (! empty($row['finding_ia_controls'])) {
                        $ia = explode(' ', $row['finding_ia_controls']);
                    } else {
                        $ia = explode(' ', $row['ia_controls']);
                    }
                    $echk = new echecklist($row['stig_id'], $row['vms_id'], (empty($row['finding_cat']) ? $row['cat'] : $row['finding_cat']), $ia, $row['short_title'], null, $row['notes'], $row['check_contents'], null);
                    $echk->set_PDI_ID($row['pdi_id']);
                    $ret[$worksheet_name]['stigs'][$row['stig_id']] = [
                        'echecklist' => $echk,
                        "{$row['tgt_name']}" => $row['finding_status'],
                        'chk_id' => $row['chk_id']
                    ];
                    if (! in_array($row['stig_id'], $stigs)) {
                        $stigs[] = $row['stig_id'];
                    }
                } else {
                    $ret[$worksheet_name]['stigs'][$row['stig_id']][$row['tgt_name']] = $row['finding_status'];
                    $ret[$worksheet_name]['stigs'][$row['stig_id']]['echecklist']->append_Notes($row['notes'] . PHP_EOL);
                }

                if ($row['chk_type'] == 'manual') {
                    $ret[$worksheet_name]['stigs'][$row['stig_id']]['chk_id'] = $row['chk_id'];
                }
            }
        }

        $where = [
            [
                'field' => 'gof.cat_id',
                'op' => (is_null($cat_id) ? IS : '='),
                'value' => $cat_id
            ]
        ];

        if (is_array($stigs) && count($stigs) && isset($stigs[0]) && is_a($stigs[0], 'stig')) {
            $where[] = [
                'field' => 'gof.stig_id',
                'op' => NOT_IN,
                'value' => $stigs,
                'sql_op' => 'AND'
            ];
        }

        if (! is_null($status)) {
            $where[] = [
                'field' => 'gof.status',
                'op' => '=',
                'value' => $status,
                'sql_op' => 'AND',
                'open-paren' => true
            ];

            if ($status == 'Not Reviewed') {
                $where[] = [
                    'field' => 'gof.status',
                    'op' => IS,
                    'value' => null,
                    'sql_op' => 'OR',
                    'close-paren' => true
                ];
            } else {
                unset($where[2]['open-paren']);
            }
        }

        if (! is_null($category)) {
            $where[] = [
                'field' => 'gof.cat',
                'op' => '=',
                'value' => $category,
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("sagacity.get_orphan_findings gof", null, $where);
        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['tgt_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            $worksheet_name = "Orphan";
            $class = [
                'U' => 1,
                'FOUO' => 2,
                'S' => 3
            ];
            foreach ($rows as $row) {
                if (! isset($ret[$worksheet_name])) {
                    $ret[$worksheet_name] = [
                        'target_list' => [],
                        'checklists' => [],
                        'stigs' => [],
                        'highest_class' => 'U'
                    ];
                }

                if (! in_array($row['chk_id'], $ret[$worksheet_name]['checklists'])) {
                    $ret[$worksheet_name]['checklists'][] = $row['chk_id'];
                }

                if (! isset($ret[$worksheet_name]['target_list'][$row['tgt_name']])) {
                    $ret[$worksheet_name]['target_list'][$row['tgt_name']] = (is_array($ret[$worksheet_name]['target_list']) ? count($ret[$worksheet_name]['target_list']) + 6 : 7);

                    $sql2 = "SELECT t.`class` " . "FROM `sagacity`.`target` t " . "WHERE t.`name` = '" . $this->conn->real_escape_string($row['tgt_name']) . "'";
                    if ($res2 = $this->conn->query($sql2)) {
                        $row2 = $res2->fetch_assoc();
                        if (isset($class[$row2['class']]) && isset($class[$ret[$worksheet_name]['highest_class']])) {
                            if ($class[$row2['class']] > $class[$ret[$worksheet_name]['highest_class']]) {
                                $ret[$worksheet_name]['highest_class'] = $row2['class'];
                            }
                        }
                    }
                }

                if (! isset($ret[$worksheet_name]['stigs'][$row['stig_id']])) {
                    if (! empty($row['finding_ia_controls'])) {
                        $ia = explode(" ", $row['finding_ia_controls']);
                    } else {
                        $ia = explode(" ", $row['ia_controls']);
                    }
                    $echk = new echecklist($row['stig_id'], $row['vms_id'], (empty($row['finding_cat']) ? $row['cat'] : $row['finding_cat']), $ia, $row['short_title'], null, $row['notes'], $row['check_contents'], null);
                    $echk->set_PDI_ID($row['pdi_id']);
                    $ret[$worksheet_name]['stigs'][$row['stig_id']] = [
                        'echecklist' => $echk,
                        $row['tgt_name'] => $row['finding_status'],
                        'chk_id' => $row['chk_id']
                    ];
                } else {
                    $ret[$worksheet_name]['stigs'][$row['stig_id']][$row['tgt_name']] = $row['finding_status'];
                    $ret[$worksheet_name]['stigs'][$row['stig_id']]['echecklist']->append_Notes($row['notes'] . "\r");
                }
            }
        }

        return $ret;
    }

    /**
     * Add a checklist to database
     *
     * @param checklist $checklist_in
     *            The checklist that we want to add to the database
     *
     * @return integer Returns the id of the checklist inserted, or 0 if failed
     */
    public function save_Checklist($checklist_in)
    {
        if (empty($checklist_in->id)) {
            $this->help->insert("sagacity.checklist", array(
                'checklist_id' => $checklist_in->checklist_id,
                'name' => $checklist_in->name,
                'description' => $checklist_in->description,
                'date' => $checklist_in->date,
                'file_name' => $checklist_in->file_name,
                'release' => $checklist_in->release,
                'ver' => $checklist_in->ver,
                'type' => $checklist_in->type,
                'icon' => $checklist_in->icon
            ), true);

            if (! $this->help->execute()) {
                Sagacity_Error::sql_handler($this->help->sql);
                $this->help->debug(E_ERROR);
            } else {
                $chk_id = $this->conn->insert_id;
            }

            if (is_array($checklist_in->sw) && count($checklist_in->sw)) {
                $fields = [
                    'chk_id',
                    'sw_id'
                ];
                $params = [];

                foreach ($checklist_in->sw as $sw) {
                    if (is_a($sw, 'software') && $sw->get_ID()) {
                        $params[] = [
                            $chk_id,
                            $sw->get_ID()
                        ];
                    }
                }

                if (count($params)) {
                    $this->help->extended_insert('checklist_software_lookup', $fields, $params, true);

                    if (! $this->help->execute()) {
                        Sagacity_Error::sql_handler($this->help->sql);
                        $this->help->debug(E_ERROR);
                    }
                }
            }
        } else {
            $this->help->update('checklist', [
                'checklist_id' => $checklist_in->checklist_id,
                'name' => $checklist_in->name,
                'description' => $checklist_in->description,
                'date' => $checklist_in->date,
                'file_name' => $checklist_in->file_name,
                'release' => $checklist_in->release,
                'ver' => $checklist_in->ver,
                'type' => $checklist_in->type,
                'icon' => $checklist_in->icon
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $checklist_in->id
                ]
            ]);

            $chk_id = $checklist_in->id;

            if (! $this->help->execute()) {
                Sagacity_Error::sql_handler($this->help->sql);
                $this->help->debug(E_ERROR);
            }

            if (is_array($checklist_in->sw) && count($checklist_in->sw)) {
                $this->help->delete("checklist_software_lookup", [
                    [
                        'field' => 'chk_id',
                        'op' => '=',
                        'value' => $checklist_in->id
                    ]
                ]);
                $this->help->execute();
                $field = [
                    'chk_id',
                    'sw_id'
                ];
                $params = [];

                foreach ($checklist_in->sw as $sw) {
                    if ($sw->get_ID()) {
                        $params[] = [
                            $chk_id,
                            $sw->get_ID()
                        ];
                    }
                }

                if (is_array($params) && count($params)) {
                    $this->help->extended_insert("checklist_software_lookup", $field, $params, true);

                    if (! $this->help->execute()) {
                        Sagacity_Error::sql_handler($this->help->sql);
                        $this->help->debug(E_ERROR);
                    }
                }
            }
        }

        return $chk_id;
    }

    // }}}
    // {{{ CVE CLASS FUNCTIONS
    /**
     * Function to retrieve CVE object
     *
     * @param string $cve_id
     *            CVE to query from the database
     *
     * @return cve|NULL Returns CVE and associated references or null is nothing found
     */
    public function get_CVE($cve_id)
    {
        $cve = null;

        $this->help->select("sagacity.cve_db", array(
            "cve_db.cve_id",
            "cve.pdi_id",
            "cve_db.seq",
            "cve_db.status",
            "cve_db.phase",
            "cve_db.phase_date",
            "cve_db.desc"
        ), array(
            array(
                'field' => 'cve_db.cve_id',
                'op' => '=',
                'value' => $cve_id
            )
        ), array(
            'table_joins' => array(
                "LEFT JOIN sagacity.cve ON cve.cve_id=cve_db.cve_id"
            )
        ));

        $row = $this->help->execute();

        if (is_array($row) && count($row) && isset($row['cve_id'])) {
            $cve_id = $row['cve_id'];

            $cve = new cve($row['pdi_id'], $row['cve_id']);
            $cve->set_Sequence($row['seq']);
            $cve->set_Status($row['status']);
            $cve->set_Phase($row['phase']);
            $cve->set_Phase_Date($row['phase_date']);
            $cve->set_Description($row['desc']);

            $this->help->select("sagacity.iavm_to_cve itc", array(
                "itc.noticeId"
            ), array(
                array(
                    'field' => "itc.cve_id",
                    'op' => '=',
                    'value' => $cve_id
                )
            ));

            $iavm_rows = $this->help->execute();
            if (is_array($iavm_rows) && count($iavm_rows) && isset($iavm_rows['noticeId'])) {
                $iavm_rows = array(
                    0 => $iavm_rows
                );
            }

            if (is_array($iavm_rows) && count($iavm_rows) && isset($iavm_rows[0])) {
                foreach ($iavm_rows as $iavm) {
                    $cve->add_IAVM($iavm['noticeId']);
                }
            }

            $this->help->select("sagacity.cve_references", array(
                'id',
                'source',
                'url',
                'val'
            ), array(
                array(
                    'field' => 'cve_seq',
                    'op' => '=',
                    'value' => $cve_id
                )
            ));

            $ref_rows = $this->help->execute();
            if (is_array($ref_rows) && count($ref_rows) && isset($ref_rows['id'])) {
                $ref_rows = array(
                    0 => $ref_rows
                );
            }

            if (is_array($ref_rows) && count($ref_rows) && isset($ref_rows[0])) {
                foreach ($ref_rows as $ref) {
                    $cve->add_Reference(new cve_reference($ref['id'], $ref['source'], $ref['url'], $ref['val']));
                }
            }
        }

        return $cve;
    }

    /**
     * Getter function to retrieve CVE's by their link to a PDI
     *
     * @param integer $pdi_id
     *            PDI ID that we want to find CVE's for
     *
     * @return NULL|array:cve Returns an array of CVEs for each one found that links to a PDI or NULL if none found
     */
    public function get_CVEs_By_PDI($pdi_id)
    {
        $ret = [];
        $sql = "SELECT " . "cve_db.`cve_id`,cve.`pdi_id`,cve_db.`seq`,cve_db.`status`," . "cve_db.`phase`,cve_db.`phase_date`,cve_db.`desc` " . "FROM `sagacity`.`cve_db` " . "LEFT JOIN `sagacity`.`cve` ON cve.`cve_id` = cve_db.`cve_id` " . "WHERE cve.`pdi_id` = " . $this->conn->real_escape_string($pdi_id);

        if ($res = $this->conn->query($sql)) {
            if (! $res->num_rows) {
                return null;
            }
            while ($row = $res->fetch_assoc()) {
                $cve_id = $row['cve_id'];

                $cve = new cve($row['pdi_id'], $row['cve_id']);

                $cve->set_Sequence($row['seq']);
                $cve->set_Status($row['status']);
                $cve->set_Phase($row['phase']);
                $cve->set_Phase_Date($row['phase_date']);
                $cve->set_Description($row['desc']);

                $sql = "SELECT itc.`noticeId` " . "FROM `sagacity`.`iavm_to_cve` itc " . "WHERE itc.`cve_id`='" . $this->conn->real_escape_string($cve_id) . "'";

                if ($res2 = $this->conn->query($sql)) {
                    if ($res2->num_rows) {
                        while ($row2 = $res2->fetch_assoc()) {
                            $cve->add_IAVM($row2['noticeId']);
                        }
                    }
                }

                $sql = "SELECT `id`,`source`,`url`,`val` " . "FROM `sagacity`.`cve_references` " . "WHERE `cve_seq`='" . $this->conn->real_escape_string($cve_id) . "'";

                if ($res2 = $this->conn->query($sql)) {
                    while ($row2 = $res2->fetch_assoc()) {
                        $cve->add_Reference(new cve_reference($row2['id'], $row2['source'], $row2['url'], $row2['val']));
                    }

                    $ret[] = $cve;
                } else {
                    Sagacity_Error::sql_handler($sql);
                    error_log($this->conn->error);
                }
            }

            return $ret;
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return null;
    }

    /**
     * Get a CVE from a external reference
     *
     * @param string $ext
     *            String of the external reference we are looking for
     *
     * @return cve|NULL Returns the CVE that references that external data point or NULL if none found
     */
    public function get_CVE_From_External($ext)
    {
        $sql = "SELECT `cve_seq` " . "FROM `sagacity`.`cve_references` " . "WHERE `url` LIKE '%" . $this->conn->real_escape_string($ext) . "%' OR " . "`val` LIKE '%" . $this->conn->real_escape_string($ext) . "%' " . "GROUP BY `cve_seq` " . "ORDER BY `cve_seq` DESC";

        if ($res = $this->conn->query($sql)) {
            if ($res->num_rows) {
                $row = $res->fetch_assoc();
                $cve = $this->get_CVE($row['cve_seq']);
                return $cve;
            }
        }

        return null;
    }

    /**
     * Update or insert a CVE
     *
     * @param array:cve $cves
     *            Array of CVEs to save to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_CVE($cves)
    {
        if (is_array($cves) && isset($cves[0]) && is_a($cves[0], 'cve')) {
            foreach ($cves as $cve) {
                $db_cve = $this->get_CVE($cve->get_CVE());

                if (! is_null($db_cve) && is_a($db_cve, 'cve')) {
                    $this->help->update("sagacity.cve_db", array(
                        'status' => $cve->get_Status(),
                        'phase' => $cve->get_Phase(),
                        'phase_date' => $cve->get_Phase_Date(),
                        'desc' => $cve->get_Description()
                    ), array(
                        array(
                            'field' => 'cve_id',
                            'op' => '=',
                            'value' => $cve->get_CVE()
                        )
                    ));

                    if (! $this->help->execute()) {
                        $this->help->debug(E_WARNING);
                        return false;
                    }

                    if (! $db_cve->get_PDI_ID() && $cve->get_PDI_ID()) {
                        $this->help->insert("sagacity.cve", array(
                            'pdi_id' => $cve->get_PDI_ID(),
                            'cve_id' => $cve->get_CVE()
                        ));

                        if (! $this->help->execute()) {
                            $this->help->debug(E_WARNING);
                            return false;
                        }
                    }

                    $vals = [];
                    foreach ($cve->get_References() as $ref) {
                        if (! $db_cve->ref_Exists($ref->get_Value())) {
                            $vals[] = [
                                $cve->get_CVE(),
                                $ref->get_Source(),
                                $ref->get_URL(),
                                $ref->get_Value()
                            ];
                        }
                    }

                    if (is_array($vals) && count($vals)) {
                        $this->help->extended_insert("cve_references", [
                            'cve_seq',
                            'source',
                            'url',
                            'val'
                        ], $vals, true);
                        if (! $this->help->execute()) {
                            $this->help->debug(E_WARNING);
                            return false;
                        }
                    }
                } else {
                    $this->help->insert("cve_db", [
                        'cve_id' => $cve->get_CVE(),
                        'seq' => $cve->get_Sequence(),
                        'status' => $cve->get_Status(),
                        'phase' => $cve->get_Phase(),
                        'phase_date' => $cve->get_Phase_Date(),
                        'desc' => $cve->get_Description()
                    ], true);

                    if (! $this->help->execute()) {
                        $this->help->debug(E_WARNING);
                        return false;
                    }

                    if ($cve->get_PDI_ID()) {
                        $this->help->insert("sagacity.cve", [
                            'pdi_id' => $cve->get_PDI_ID(),
                            'cve_id' => $cve->get_CVE()
                        ], true);

                        if (! $this->help->execute()) {
                            $this->help->debug(E_WARNING);
                            return false;
                        }
                    }

                    if (is_array($cve->get_References()) && count($cve->get_References())) {
                        $ref_vals = [];
                        foreach ($cve->get_References() as $ref) {
                            $ref_vals[] = [
                                $cve->get_CVE(),
                                $ref->get_Source(),
                                $ref->get_URL(),
                                $ref->get_Value()
                            ];
                        }

                        if (is_array($ref_vals) && count($ref_vals)) {
                            $this->help->extended_insert("cve_references", [
                                'cve_seq',
                                'source',
                                'url',
                                'val'
                            ], $ref_vals, true);
                            if (! $this->help->execute()) {
                                $this->help->debug(E_WARNING);
                                return false;
                            }
                        }
                    }

                    if ($cve->get_XML()) {
                        $this->help->insert("cve_web", [
                            'cve_id' => $cve->get_CVE(),
                            'xml' => $cve->get_XML()
                        ], true);

                        $this->help->execute();
                    }
                }
            }
        }

        return true;
    }

    // }}}
    // {{{ ECHECKLIST CLASS FUNCTIONS
    /**
     * Get an eChecklist for a checklist and list of targets
     *
     * @param mixed $ref
     *            The reference to search for (can consist of any data that is referenced in an eChecklist line
     * @param integer $chk_id
     *
     * @return NULL|echecklist Returns eChecklist for associated checklists and reference
     */
    public function get_eChecklist($ref, $chk_id)
    {
        $ret = null;
        $where = [];

        if (is_a($ref, "stig")) {
            $where[] = [
                'field' => 's.stig_id',
                'op' => '=',
                'value' => $ref->get_ID()
            ];
        } elseif (is_a($ref, "golddisk")) {
            $where[] = [
                'field' => 'v.vms_id',
                'op' => '=',
                'value' => $ref->get_ID()
            ];
        } elseif (is_a($ref, "pdi")) {
            $where[] = [
                'field' => 'pdi.id',
                'op' => '=',
                'value' => $ref->get_ID()
            ];
        } else {
            error_log("No reference to search for");
            return $ret;
        }

        $this->help->select("pdi_catalog pdi", [
            "pdi.id AS 'pdi_id'",
            "s.stig_id",
            "v.vms_id",
            "pdi.short_title",
            "IF(pdi.cat=1,'I',IF(pdi.cat=2,'II',IF(pdi.cat=3,'III',''))) as 'cat'"
        ], $where, [
            'table_joins' => [
                "LEFT JOIN stigs s ON s.pdi_id = pdi.id",
                "LEFT JOIN golddisk v ON v.pdi_id = pdi.id"
            ],
            'group' => 's.stig_id'
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['pdi_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret = new echecklist($row['stig_id'], $row['vms_id'], $row['cat'], null, $row['short_title'], null, null, null, null);
                $ret->set_PDI_ID($row['pdi_id']);

                $this->help->select("pdi_checklist_lookup pcl", [
                    'pcl.check_contents'
                ], [
                    [
                        'field' => 'pcl.checklist_id',
                        'op' => IN,
                        'value' => (is_array($chk_id) ? implode(",", $chk_id) : $chk_id)
                    ],
                    [
                        'field' => 'pcl.pdi_id',
                        'op' => '=',
                        'value' => $row['pdi_id'],
                        'sql_op' => 'AND'
                    ]
                ], [
                    'table_joins' => [
                        "JOIN sagacity.checklist c ON c.id = pcl.checklist_id"
                    ],
                    'order' => "FIELD(c.`type`, 'manual', 'iavm', 'policy', 'benchmark')"
                ]);

                $row2 = $this->help->execute();
                if (is_array($row2) && count($row2) && isset($row2['check_contents'])) {
                    $ret->set_Check_Contents($row2['check_contents']);
                }
            }
        }

        return $ret;
    }

    // }}}
    // {{{ FILTER CLASS FUNCTIONS
    /**
     * Getter function for search filters
     *
     * @param string $type
     *
     * @return array:string
     */
    public function get_Filters($type, $name = null)
    {
        $ret = [];
        $sql = "SELECT `type`, `name`, `criteria` " . "FROM `sagacity`.`search_filters` " . "WHERE `type` = '" . $this->conn->real_escape_string($type) . "'";

        if (! is_null($name)) {
            $sql .= " AND `name` = '" . $this->conn->real_escape_string($name) . "'";
        }

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $ret[] = array(
                    'type' => $row['type'],
                    'name' => $row['name'],
                    'criteria' => $row['criteria']
                );
            }

            return $ret;
        } else {
            error_log($this->conn->error);
            Sagacity_Error::sql_handler($sql);
        }

        return [];
    }

    /**
     * Save function for a search filter
     *
     * @param string $type
     * @param string $name
     * @param string $criteria
     *
     * @return string
     */
    public function save_Filter($type, $name, $criteria)
    {
        $this->help->insert("sagacity.search_filters", [
            'name' => $name,
            'type' => $type,
            'criteria' => $criteria
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ FINDING CLASS FUNCTIONS
    /**
     * Get finding(s) for a specific target from the database
     *
     * @param target $tgt
     *            The target that we want findings for
     * @param stig|golddisk|iavm|nessus $ref
     *            [optional]
     *            Get a finding associated with a specific PDI (default null)
     * @param scan $scan
     *            [optional]
     *            Get findings associated with a specific scan (default null)
     * @param boolean $orphan_only
     *            [optional]
     *            Only retrieve orphaned findings (default false)
     * @param string $status
     *            [optional]
     *            Limit the retrieval to findings with this status (default null)
     *
     * @return array:finding|NULL Returns array of findings
     */
    public function get_Finding($tgt, $ref = null, $scan = null, $orphan_only = false, $status = null)
    {
        $ret = null;
        $where = [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt->get_ID()
            ]
        ];

        if (! is_null($scan)) {
            $where[] = [
                'field' => 'scan_id',
                'op' => '=',
                'value' => $scan->get_ID(),
                'sql_op' => 'AND'
            ];
        }

        if (! is_null($ref) && method_exists($ref, 'get_PDI_ID')) {
            $where[] = [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $ref->get_PDI_ID(),
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("sagacity.findings", null, $where);

        if (! is_null($status)) {
            $this->help->sql = "SELECT " .
            "f.`id`, {$tgt->get_ID()} as 'tgt_id', pdi.`id` as 'pdi_id', f.`scan_id`, " .
            "f.`notes`, f.`change_id`, f.`orig_src`, f.`finding_itr`, f.`cat`, " .
            "IF(f.`findings_status_id` IS NOT NULL, " .
            "f.`findings_status_id`, " .
            "(SELECT fs.`id` " .
            "FROM `sagacity`.`findings_status` fs " .
            "WHERE fs.`status` = '{$this->conn->real_escape_string($status)}')" .
            ") as 'findings_status' " .
            "FROM `sagacity`.`pdi_catalog` pdi " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` lookup ON lookup.`pdi_id` = pdi.`id` " .
            "LEFT JOIN `sagacity`.`target_checklist` tc ON tc.`chk_id` = lookup.`checklist_id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pdi.`id` AND f.`tgt_id` = {$tgt->get_ID()} " .
            "WHERE tc.`tgt_id` = {$tgt->get_ID()} AND " .
            "(f.`findings_status_id` = (" .
            "SELECT fs.`id` " .
            "FROM `sagacity`.`findings_status` fs " .
            "WHERE fs.`status` = '{$this->conn->real_escape_string($status)}'" . ") OR " .
            "f.`findings_status_id` IS NULL) " .
            "GROUP BY pdi.id";
        }

        if ($orphan_only) {
            $this->help->select("sagacity.findings f", [
                'f.*'
            ], [
                [
                    'field' => 'f.tgt_id',
                    'op' => '=',
                    'value' => $tgt->get_ID()
                ],
                [
                    'field' => 'c.name',
                    'op' => '=',
                    'value' => 'Orphan',
                    'sql_op' => 'AND'
                ]
            ], [
                'table_joins' => [
                    "LEFT JOIN pdi_checklist_lookup pcl ON f.pdi_id=pcl.pdi_id",
                    "LEFT JOIN target_checklist tc ON tc.chk_id=pcl.checklist_id",
                    "LEFT JOIN checklist c ON pcl.checklist_id=c.id"
                ]
            ]);
        }

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['pdi_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $find = new finding($row['tgt_id'], $row['pdi_id'], $row['scan_id'], $row['findings_status_id'], $row['notes'], $row['change_id'], $row['orig_src'], $row['finding_itr']);
                $find->set_Category($row['cat']);
                $this->get_Finding_Notes($find);

                $this->help->select("finding_controls", [
                    'ia_control'
                ], [
                    [
                        'field' => 'tgt_id',
                        'op' => '=',
                        'value' => $row['tgt_id']
                    ],
                    [
                        'field' => 'pdi_id',
                        'op' => '=',
                        'value' => $row['pdi_id'],
                        'sql_op' => 'AND'
                    ]
                ]);

                $rows2 = $this->help->execute();
                if (is_array($rows2) && count($rows2) && isset($rows2['ia_control'])) {
                    $rows2 = [
                        0 => $rows2
                    ];
                }
                if (is_array($rows2) && count($rows2) && isset($rows2[0])) {
                    foreach ($rows2 as $row2) {
                        $find->add_IA_Control($row2['ia_control']);
                    }
                } else {
                    $this->help->select("ia_controls", [
                        "CONCAT(`type`, '-', `type_id`) AS 'ia_control'"
                    ], [
                        [
                            'field' => 'pdi_id',
                            'op' => '=',
                            'value' => $row['pdi_id']
                        ]
                    ]);
                    $rows2 = $this->help->execute();
                    if (is_array($rows2) && count($rows2) && isset($rows2['ia_control'])) {
                        $rows2 = [
                            0 => $rows2
                        ];
                    }
                    if (is_array($rows2) && count($rows2) && isset($rows2[0])) {
                        foreach ($rows2 as $row2) {
                            $find->add_IA_Control($row2['ia_control']);
                        }
                    }
                }

                $ret[$find->get_PDI_ID()] = $find;
            }
        }

        return $ret;
    }

    /**
     * Function to get the findings that are assigned to specific controls
     *
     * @param ste $ste
     * @param proc_ia_controls $ia_ctrl
     * @param string $status
     * @return array:finding |NULL
     */
    public function get_Findings_by_Control($ste, $ia_ctrl, $status = null)
    {
        if (! is_null($status)) {
            if ($status == "Open") {
                $status = " AND (fs.`status` = 'Open' OR fs.`status` = 'Exception')";
            } else {
                $status = " AND fs.`status` = '" . $this->conn->real_escape_string($status) . "'";
            }
        }

        $sql = <<<EOQ
SELECT
    f.`tgt_id`, f.`pdi_id`, f.`scan_id`, f.`findings_status_id` as 'findings_status',
    f.`notes`, f.`change_id`, f.`orig_src`, f.`finding_itr`, f.`cat`
FROM `sagacity`.`findings` f
JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id` = fs.`id`
JOIN `sagacity`.`stigs` s ON s.`pdi_id` = f.`pdi_id`
JOIN `sagacity`.`target` t ON t.`id` = f.`tgt_id`
JOIN `sagacity`.`finding_controls` fc ON fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id`
WHERE
    t.`ste_id` = {$ste->get_ID()} AND
    fc.`ia_control` = '{$this->conn->real_escape_string($ia_ctrl->get_Control_ID())}'
    $status
GROUP BY f.`pdi_id`
ORDER BY f.`cat`, s.`stig_id`

EOQ;

        if ($res = $this->conn->query($sql)) {
            $ret = [];
            while ($row = $res->fetch_assoc()) {
                $find = new finding($row['tgt_id'], $row['pdi_id'], $row['scan_id'], $row['findings_status'], $row['notes'], $row['change_id'], $row['orig_src'], $row['finding_itr']);
                $find->set_Category($row['cat']);

                $sql2 = "SELECT `ia_control` FROM `sagacity`.`finding_controls` WHERE `tgt_id` = {$row['tgt_id']} AND `pdi_id` = {$row['pdi_id']}";

                if ($res2 = $this->conn->query($sql2)) {
                    if ($res2->num_rows) {
                        while ($row2 = $res2->fetch_assoc()) {
                            $find->add_IA_Control($row2['ia_control']);
                        }
                    } else {
                        $sql2 = "SELECT CONCAT(`type`, '-', `type_id`) AS 'ia_control' FROM `sagacity`.`ia_controls` WHERE `pdi_id` = " . $row['pdi_id'];
                        if ($res2 = $this->conn->query($sql2)) {
                            while ($row2 = $res2->fetch_assoc()) {
                                $find->add_IA_Control($row2['ia_control']);
                            }
                        }
                    }
                }

                $ret[] = $find;
            }

            return $ret;
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }
        return null;
    }

    /**
     * Function to return the host name of the targets that have this finding
     *
     * @param ste $ste
     * @param pdi $pdi
     *
     * @return string
     */
    public function get_Affected_Hosts_by_PDI($ste, $pdi)
    {
        $sql = <<<EOQ
SELECT (
    SELECT GROUP_CONCAT(DISTINCT t.`name` SEPARATOR ', ')) AS 'name'
    FROM `sagacity`.`findings` f
    JOIN `sagacity`.`target` t ON f.`tgt_id` = t.`id`
    WHERE
        t.`ste_id` = {$ste->get_ID()} AND
        f.`pdi_id` = {$pdi->get_ID()}

EOQ;

        if ($res = $this->conn->query($sql)) {
            return $res->fetch_assoc()['name'];
        }

        return '';
    }

    /**
     * Function to return stigs that are not in the systems MAC and Classification
     *
     * @param ste $ste
     *
     * @return array:stig
     */
    public function get_Findings_Not_in_System($ste)
    {
        $ret = [];
        $this->help->create_table("unaccounted_for_findings", [
            [
                'field' => 'pdi_id',
                'datatype' => 'int(11)',
                'option' => 'UNIQUE NOT NULL'
            ]
        ]);
        $this->help->execute();

        $sql = "INSERT IGNORE INTO `unaccounted_for_findings` (`pdi_id`) SELECT DISTINCT(f.`pdi_id`) " .
            "FROM `findings` f JOIN `target` t ON t.`id` = f.`tgt_id` " .
            "WHERE t.`ste_id` = {$ste->get_ID()}";
        $this->conn->real_query($sql);

        $class = 'cl';
        if ($ste->get_System()->get_Classification() == 'Public') {
            $class = 'pub';
        } elseif ($ste->get_System()->get_Classification() == 'Sensitive') {
            $class = 'sen';
        }

        $sql = "DELETE FROM `unaccounted_for_findings` WHERE `pdi_id` IN (SELECT ia.`pdi_id` " .
            "FROM `proc_level_type` plt " .
            "JOIN `ia_controls` ia ON CONCAT(ia.`type`, '-', ia.`type_id`) = plt.`proc_control` " .
            "WHERE " .
                "plt.`level` = {$ste->get_System()->get_MAC()} AND " .
                "plt.`class` = '$class')";
        $this->conn->real_query($sql);

        $sql = "SELECT s.`stig_id` FROM `unaccounted_for_findings` uaf JOIN `stigs` s ON s.`pdi_id` = uaf.`pdi_id`";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $stig = $this->get_Stig($row['stig_id']);
                if (is_array($stig) && count($stig) && isset($stig[0]) && is_a($stig[0], 'stig')) {
                    $stig = $stig[0];
                }
                if (! preg_match("/^\d{5}$/", $stig->get_ID())) {
                    $ret[] = $stig;
                }
            }
        }

        return $ret;
    }

    /**
     * Get count of all findings with the status passed in
     *
     * @param integer $cat_id
     *            The category we are searching
     * @param string $status
     *            The status to look for
     * @param integer $cat
     *            [optional]
     *            The CAT/severity level
     * @param proc_ia_controls $ctrl
     *            [optional]
     *            A IA control to filter for
     *
     * @return integer Returns the number of findings in the category that have the passed in status, severity, and control
     */
    public function get_Finding_Count_By_Status($cat_id, $status, $cat = null, $ctrl = null)
    {
        $joins = [
            "JOIN target_checklist tc ON t.id = tc.tgt_id",
            "JOIN pdi_checklist_lookup pcl ON pcl.checklist_id = tc.chk_id",
            "LEFT JOIN findings f ON f.pdi_id = pcl.pdi_id AND t.id = f.tgt_id",
            "LEFT JOIN findings_status fs ON fs.id = f.findings_status_id"
        ];
        if (! is_null($ctrl)) {
            $joins[] = "JOIN finding_controls fc ON fc.tgt_id = f.tgt_id AND fc.pdi_id = f.pdi_id";
        }

        $where = [
            [
                'field' => 't.cat_id',
                'value' => $cat_id
            ],
            [
                'field' => 'fs.status',
                'value' => $status,
                'sql_op' => 'AND',
                'open-paren' => true
            ]
        ];

        if ($status == 'Not Reviewed') {
            $where[] = [
                'field' => 'fs.status',
                'op' => IS,
                'value' => null,
                'sql_op' => 'OR',
                'close-paren' => true
            ];
        } else {
            $where[] = [
                'close-paren' => true
            ];
        }

        if (! is_null($cat) && is_numeric($cat)) {
            $where[] = [
                'field' => 'f.cat',
                'value' => $cat,
                'sql_op' => 'AND'
            ];
        }

        if (! is_null($ctrl) && is_a($ctrl, 'proc_ia_controls')) {
            $where[] = [
                'field' => 'fc.ia_control',
                'value' => $ctrl->get_Control_ID(),
                'sql_op' => 'AND'
            ];
        }

        $field = ($status == 'Not Reviewed' ? "COUNT(DISTINCT(pcl.pdi_id)) AS 'count'" : "COUNT(DISTINCT(f.id)) AS 'count'");
        $this->help->select_count("target t", $where, [
            'table_joins' => $joins
        ]);
        $this->help->sql = str_replace("COUNT(1) AS 'count'", $field, $this->help->sql);

        $cnt = $this->help->execute();

        $joins = [
            "JOIN pdi_checklist_lookup pcl ON pcl.checklist_id = c.id",
            "JOIN findings f ON f.pdi_id = pcl.pdi_id",
            "LEFT JOIN findings_status fs ON f.findings_status_id = fs.id",
            "JOIN target t ON t.id = f.tgt_id"
        ];

        if (! is_null($ctrl) && is_a($ctrl, 'proc_ia_controls')) {
            $joins[] = "JOIN finding_controls fc ON fc.tgt_id = f.tgt_id AND fc.pdi_id = f.pdi_id";
        }

        $where = [
            [
                'field' => 't.cat_id',
                'value' => $cat_id
            ],
            [
                'field' => 'c.name',
                'value' => 'Orphan',
                'sql_op' => 'AND'
            ],
            [
                'field' => 'fs.status',
                'value' => $status,
                'sql_op' => 'AND',
                'open-paren' => true
            ]
        ];

        if ($status == 'Not Reviewed') {
            $where[] = [
                'field' => 'fs.status',
                'op' => IS,
                'value' => null,
                'sql_op' => 'OR',
                'close-paren' => true
            ];
        } else {
            $where[] = [
                'close-paren' => true
            ];
        }

        if (! is_null($cat) && is_numeric($cat)) {
            $where[] = [
                'field' => 'f.cat',
                'value' => $cat,
                'sql_op' => 'AND'
            ];
        }

        if (! is_null($ctrl) && is_a($ctrl, 'proc_ia_controls')) {
            $where[] = [
                'field' => 'fc.ia_control',
                'value' => $ctrl->get_Control_ID(),
                'sql_op' => 'AND'
            ];
        }

        $this->help->select_count("checklist c", $where, array(
            'table_joins' => $joins
        ));
        $this->help->sql = str_replace("COUNT(1) AS 'count'", $field, $this->help->sql);

        $cnt += $this->help->execute();

        return $cnt;
    }

    /**
     * Get count of all findings with the status passed in
     *
     * @param ste $ste
     *            The category we are searching
     * @param string $status
     *            The status to look for
     * @param integer $cat
     *            The CAT/severity level
     * @param proc_ia_controls $ctrl
     *            A IA control to filter for
     *
     * @return integer Returns the number of findings with status
     */
    public function get_STE_Finding_Count_By_Status($ste, $status, $cat = null, $ctrl = null)
    {
        $field = ($status == 'Not Reviewed' ? "SELECT COUNT(DISTINCT(pcl.`pdi_id`))" : "SELECT COUNT(DISTINCT(f.`id`))");
        $ctrl_join = (! is_null($ctrl) ? "JOIN `sagacity`.`finding_controls` fc ON fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id` " : "");
        $status_clause = ($status == 'Not Reviewed' ? " OR fs.`status` IS NULL" : "");
        $cat_clause = (! is_null($cat) ? "AND f.`cat` = $cat " : "");
        $ctrl_clause = (! is_null($ctrl) ? "AND fc.`ia_control` = '{$ctrl->get_Control_ID()}' " : "");
        $sql = <<<EOQ
SELECT (
    $field
    FROM `sagacity`.`target` t
    LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id` = tc.`tgt_id`
    LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id` = tc.`chk_id`
    LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pcl.`pdi_id` AND t.`id` = f.`tgt_id`
    LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id` = f.`findings_status_id`
    $ctrl_join
    WHERE
        t.`ste_id` = {$this->conn->real_escape_string($ste->get_ID())} AND
        (
            fs.`status` = '{$this->conn->real_escape_string($status)}'
            $status_clause
        )
        $cat_clause
        $ctrl_clause
)
 +
(
    $field
    FROM `sagacity`.`checklist` c
    LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id` = c.`id`
    LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pcl.`pdi_id`
    LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id` = fs.`id`
    JOIN `sagacity`.`target` t ON t.`id` = f.`tgt_id`
    $ctrl_join
    WHERE
        t.`ste_id` = {$this->conn->real_escape_string($ste->get_ID())} AND
        c.`name` = 'Orphan' AND
        (
            fs.`status` = '{$this->conn->real_escape_string($status)}'
            $status_clause
        )
        $cat_clause
        $ctrl_clause
) AS 'sum_count'

EOQ;

        if ($res = $this->conn->query($sql)) {
            return $res->fetch_assoc()['sum_count'];
        } else {
            return 0;
        }
    }

    /**
     * Get count of all findings with the status passed in
     *
     * @param target $tgt
     *            The target we are searching
     * @param string $status
     *            The status to look for
     * @param integer $cat
     *            [optional]
     *            The CAT/severity level
     * @param proc_ia_controls $ctrl
     *            [optional]
     *            A IA control to filter for
     * @param array $chk_ids
     *            [optional]
     * @param boolean $is_orphan
     *            [optional]
     *
     * @return integer Returns the number of findings with status 'False Positives'
     */
    public function get_Host_Finding_Count_By_Status($tgt, $status, $cat = null, $ctrl = null, $chk_ids = null, $is_orphan = false)
    {
        if (! $is_orphan) {
            $sql = "SELECT (SELECT COUNT(DISTINCT(pcl.`pdi_id`)) " .
            "FROM `sagacity`.`target` t " .
            "LEFT JOIN `sagacity`.`target_checklist` tc ON t.`id` = tc.`tgt_id` " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id` = tc.`chk_id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id` = f.`findings_status_id` " .
            (! is_null($ctrl) ? "JOIN `sagacity`.`finding_controls` fc ON fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id` " : "") .
            "WHERE t.`id` = {$this->conn->real_escape_string($tgt->get_ID())} AND " .
            "(fs.`status` = '{$this->conn->real_escape_string($status)}' " .
            ($status == 'Not Reviewed' ? " OR fs.`status` IS NULL" : "") . ") " .
            (! is_null($cat) ? "AND f.`cat` = $cat " : "") .
            (! is_null($ctrl) ? "AND fc.`ia_control` = '{$ctrl->get_Control_ID()}' " : "") .
            (! is_null($chk_ids) ? "AND pcl.`checklist_id` IN (" . implode(", ", $chk_ids) . ") " : "") .
            ")";
        } else {
            $sql = "SELECT (SELECT COUNT(DISTINCT(pcl.`pdi_id`)) " .
            "FROM `sagacity`.`checklist` c " .
            "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id` = c.`id` " .
            "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pcl.`pdi_id` " .
            "LEFT JOIN `sagacity`.`findings_status` fs ON f.`findings_status_id` = fs.`id` " .
            "JOIN `sagacity`.`target` t ON t.`id` = f.`tgt_id` " .
            (! is_null($ctrl) ? "JOIN `sagacity`.`finding_controls` fc ON fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id` " : "") .
            "WHERE t.`id` = {$this->conn->real_escape_string($tgt->get_ID())} AND " .
            "c.`name` = 'Orphan' AND " .
            "(fs.`status` = '{$this->conn->real_escape_string($status)}' " .
            ($status == 'Not Reviewed' ? " OR fs.`status` IS NULL" : "") . ") " .
            (! is_null($cat) ? "AND f.`cat` = $cat " : "") .
            (! is_null($ctrl) ? "AND fc.`ia_control` = '{$ctrl->get_Control_ID()}' " : "") .
            ")";
        }
        $sql .= " AS 'sum_count'";

        if ($res = $this->conn->query($sql)) {
            return $res->fetch_assoc()['sum_count'];
        } else {
            return 0;
        }
    }

    /**
     * Function for getting number of targets that have a finding in this control
     *
     * @param ia_control $ctrl
     * @param ste $ste
     * @param string $status
     *
     * @return int
     */
    public function get_Control_Finding_Count($ctrl, $ste, $status, $cat = null)
    {
        $sql = "SELECT " .
        "IFNULL((SELECT COUNT(1) " .
        "FROM `target` t " .
        "LEFT JOIN `target_checklist` tc ON t.`id` = tc.`tgt_id` " .
        "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id` = tc.`chk_id` " .
        "LEFT JOIN `findings` f ON f.`pdi_id` = pcl.`pdi_id` AND t.`id` = f.`tgt_id` " .
        "LEFT JOIN `findings_status` fs ON fs.`id` = f.`findings_status_id` " .
        "LEFT JOIN `finding_controls` fc ON fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id` " .
        "WHERE " .
        "(fs.`status` = '$status' " .
        ($status == 'Open' ? " OR fs.`status` = 'Exception'" : "") .
        ($status == 'Not a Finding' ? " OR fs.`status` = 'Not Applicable'" : "") .
        ($status == 'Not Reviewed' ? " OR fs.`status` IS NULL" : "") .
        ") AND " .
        (! is_null($cat) ? "f.`cat` = $cat AND " : "") .
        (! is_null($ctrl) ? "fc.`ia_control` = '{$ctrl->get_Control_ID()}' AND " : "") .
        "t.`ste_id` = $ste " .
        "GROUP BY f.`pdi_id`" . "), 0)" .
        " + " .
        "IFNULL((SELECT COUNT(1) " .
        "FROM `checklist` c " .
        "LEFT JOIN `pdi_checklist_lookup` pcl ON pcl.`checklist_id` = c.`id` " .
        "LEFT JOIN `findings` f ON f.`pdi_id` = pcl.`pdi_id` " .
        "LEFT JOIN `findings_status` fs ON f.`findings_status_id` = fs.`id` " .
        "LEFT JOIN `target` t ON t.`id` = f.`tgt_id` " .
        "LEFT JOIN `finding_controls` fc ON fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id` " .
        "WHERE " .
        "c.`name` = 'Orphan' AND " .
        "(fs.`status` = '$status' " .
        ($status == 'Open' ? " OR fs.`status` = 'Exception'" : "") .
        ($status == 'Not a Finding' ? " OR fs.`status` = 'Not Applicable'" : "") .
        ($status == 'Not Reviewed' ? " OR fs.`status` IS NULL" : "") . ") AND " .
        (! is_null($cat) ? "f.`cat` = $cat AND " : "") .
        (! is_null($ctrl) ? "fc.`ia_control` = '{$ctrl->get_Control_ID()}' AND " : "") .
        "t.`ste_id` = $ste " .
        "GROUP BY f.`pdi_id`" . "), 0) AS 'sum_count'";
        if ($res = $this->conn->query($sql)) {
            return $res->fetch_assoc()['sum_count'];
        } else {
            return 0;
        }
    }
    
    /**
     * Getter method to get finding notes
     *
     * @param finding $find
     */
    public function get_Finding_Notes(finding &$find)
    {
        $this->help->select("analyst_notes", ['note'], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $find->get_Tgt_ID()
            ],
            [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $find->get_PDI_ID(),
                'sql_op' => 'AND'
            ]
        ]);
        $row = $this->help->execute();
        if(isset($row['note'])) {
            $find->set_Analyst_Notes($row['note']);
        }
        
        $this->help->select("scan_notes sn", ['sn.note', 'src.name'], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $find->get_Tgt_ID()
            ],
            [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $find->get_PDI_ID(),
                'sql_op' => 'AND'
            ],
            [
                'field' => 'scan_id',
                'op' => '=',
                'value' => $find->get_Scan_ID(),
                'sql_op' => 'AND'
            ]
        ], [
            'table_joins' => [
                "JOIN scans s ON sn.scan_id = s.id",
                "JOIN sources src ON src.id = s.src_id"
            ]
        ]);
        $rows = $this->help->execute();
        if(is_array($rows) && count($rows) && isset($rows[0])) {
            $notes = $find->get_Scanner_Notes();
            foreach($rows as $row) {
                $notes .= $row['name'] . ":\r" . $row['note'];
            }
            $find->set_Scanner_Notes($notes);
        } elseif(isset($rows['note'])) {
            $notes = $find->get_Scanner_Notes();
            $notes .= $rows['name'] . ":\r" . $rows['note'];
            $find->set_Scanner_Notes($notes);
        }
    }

    /**
     * Function to determine how pervasive a finding is across all targets
     *
     * @todo - FINISH
     *
     * @param ste $ste
     * @param proc_ia_controls $ia_ctrl
     * @param string $status
     */
    public function get_Finding_Pervasivity_by_Control($ste, $ia_ctrl, $status = null)
    {}

    /**
     * Function to return all the possible finding statuses
     *
     * @return array:finding_status
     */
    public function get_Finding_Statuses()
    {
        $this->help->select("sagacity.findings_status", null);
        $rows = $this->help->execute();
        $ret = [];

        if(is_array($rows) && count($rows) && isset($rows[0])) {
            foreach($rows as $row) {
                $s = new finding_status();
                $s->id = $row['id'];
                $s->status = $row['status'];

                $ret[] = $s;
            }
        } elseif(is_array($rows) && count($rows) && isset($rows['id'])) {
            $s = new finding_status();
            $s->id = $rows['id'];
            $s->status = $rows['status'];

            $ret[] = $s;
        }

        return $ret;
    }

    /**
     * Function to compare the findings from two different targets
     *
     * @param target $left_tgt
     * @param target $right_tgt
     *
     * @return array
     */
    public function get_Finding_Comparrison($left_tgt, $right_tgt)
    {
        $ret = [];
        $left_sql = "SELECT " .
        "s.`stig_id`, pcl.`check_contents`, " .
        "tgt.`id` AS 'tgt_id', tgt.`name` AS 'tgt_name', " .
        "IF(f.`cat` IS NULL, pdi.`cat`, f.`cat`) AS 'cat', f.`notes`, " .
        "IF(f.`findings_status_id` IS NULL, 'Not Reviewed', fs.`status`) AS 'finding_status', " .
        "(SELECT GROUP_CONCAT(fc.`ia_control` SEPARATOR ' ') " .
        "FROM `sagacity`.`finding_controls` fc " .
        "WHERE fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id`) AS 'finding_ia_controls', " .
        "(SELECT GROUP_CONCAT(DISTINCT CONCAT(ia.`type`, '-', ia.`type_id`) SEPARATOR ' ') " .
        "FROM `sagacity`.`ia_controls` ia " .
        "WHERE ia.`pdi_id` = pcl.`pdi_id`) AS 'ia_controls' " .
        "FROM `sagacity`.`checklist` chk " .
        "JOIN `sagacity`.`target_checklist` tc ON tc.`chk_id` = chk.`id` " .
        "JOIN `sagacity`.`target` tgt ON tgt.`id` = tc.`tgt_id` " .
        "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id` = chk.`id` " .
        "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pcl.`pdi_id` AND f.`tgt_id` = tgt.`id` " .
        "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id` = f.`findings_status_id` " .
        "LEFT JOIN `sagacity`.`stigs` s ON s.`pdi_id` = pcl.`pdi_id` " .
        "LEFT JOIN `sagacity`.`pdi_catalog` pdi ON pdi.`id` = pcl.`pdi_id` " .
        "WHERE tgt.`id` = {$left_tgt->get_ID()} " .
        "GROUP BY s.`stig_id`, tgt.`name` " .
        "ORDER BY s.`stig_id`, FIELD(chk.`type`, 'manual', 'iavm', 'policy', 'benchmark')";
        $right_sql = "SELECT " .
        "s.`stig_id`, pcl.`check_contents`, " .
        "tgt.`id` AS 'tgt_id', tgt.`name` AS 'tgt_name', " .
        "IF(f.`cat` IS NULL, pdi.`cat`, f.`cat`) AS 'cat', f.`notes`, " .
        "IF(f.`findings_status_id` IS NULL, 'Not Reviewed', fs.`status`) AS 'finding_status', " .
        "(SELECT GROUP_CONCAT(fc.`ia_control` SEPARATOR ' ') " .
        "FROM `sagacity`.`finding_controls` fc " .
        "WHERE fc.`tgt_id` = f.`tgt_id` AND fc.`pdi_id` = f.`pdi_id`) AS 'finding_ia_controls', " .
        "(SELECT GROUP_CONCAT(DISTINCT CONCAT(ia.`type`, '-', ia.`type_id`) SEPARATOR ' ') " .
        "FROM `sagacity`.`ia_controls` ia " .
        "WHERE ia.`pdi_id` = pcl.`pdi_id`) AS 'ia_controls' " .
        "FROM `sagacity`.`checklist` chk " .
        "JOIN `sagacity`.`target_checklist` tc ON tc.`chk_id` = chk.`id` " .
        "JOIN `sagacity`.`target` tgt ON tgt.`id` = tc.`tgt_id` " .
        "LEFT JOIN `sagacity`.`pdi_checklist_lookup` pcl ON pcl.`checklist_id` = chk.`id` " .
        "LEFT JOIN `sagacity`.`findings` f ON f.`pdi_id` = pcl.`pdi_id` AND f.`tgt_id` = tgt.`id` " .
        "LEFT JOIN `sagacity`.`findings_status` fs ON fs.`id` = f.`findings_status_id` " .
        "LEFT JOIN `sagacity`.`stigs` s ON s.`pdi_id` = pcl.`pdi_id` " .
        "LEFT JOIN `sagacity`.`pdi_catalog` pdi ON pdi.`id` = pcl.`pdi_id` " .
        "WHERE tgt.`id` = {$right_tgt->get_ID()} " .
        "GROUP BY s.`stig_id`, tgt.`name` " .
        "ORDER BY s.`stig_id`, FIELD(chk.`type`, 'manual', 'iavm', 'policy', 'benchmark')";

        if ($res = $this->conn->query($left_sql)) {
            while ($row = $res->fetch_assoc()) {
                $ret['left'][$row['stig_id']] = array(
                    'stig_id' => $row['stig_id'],
                    'cat' => $row['cat'],
                    'ia_controls' => (! empty($row['finding_ia_controls']) ? $row['finding_ia_controls'] : $row['ia_controls']),
                    'status' => $row['finding_status'],
                    'notes' => $row['notes']
                );
            }
        }

        if ($res = $this->conn->query($right_sql)) {
            while ($row = $res->fetch_assoc()) {
                $ret['right'][$row['stig_id']] = array(
                    'stig_id' => $row['stig_id'],
                    'cat' => $row['cat'],
                    'ia_controls' => (! empty($row['finding_ia_controls']) ? $row['finding_ia_controls'] : $row['ia_controls']),
                    'status' => $row['finding_status'],
                    'notes' => $row['notes']
                );

                if (! isset($ret['left'][$row['stig_id']])) {
                    $ret['left'][$row['stig_id']] = null;
                }
            }
        }

        return $ret;
    }

    // @TODO - modify to accept finding and array:finding
    /**
     * Add a finding
     *
     * @param scan $scan
     *            Scan that found this item
     * @param array:target|target $tgts
     *            Array of targets or a single target that have this finding
     * @param array|finding $finding_data
     *            Array of data associated with the finding<br />
     *            [0] => 'stig id'<br />
     *            [1] => 'vms id'<br />
     *            [2] => 'category level (I, II, III)'<br />
     *            [3] => 'ia controls (space delimited)'<br />
     *            [4] => 'short title'<br />
     *            [5...n] => 'target status'<br />
     *            [n+1] => 'notes'<br />
     *            [n+2] => 'check contents'<br />
     *            [n+3] => 'missing pdi'
     */
    public function add_Finding($scan, $tgts, $finding_data)
    {
        global $cmd;
        set_time_limit(0);
        $host_count = 0;
        $ref = null;

        if (is_array($tgts)) {
            $host_count = count($tgts);
        } else {
            $host_count ++;
        }

        if (preg_match('/\d\.\d+/', $finding_data[0])) {
            $finding_data[0] = str_pad($finding_data[0], 5, "0");
        }
        $stig_id = $finding_data[0];
        $vms_id = preg_replace("/V0+/i", "V-", $finding_data[1]);
        $cat_lvl = substr_count($finding_data[2], 'I');
        $ia_controls = $finding_data[3];
        $short_title = $finding_data[4];
        $notes = $finding_data[self::FIRST_ECHECKLIST_HOST_COL + $host_count];

        if (preg_match('/SV\-.*_rule/', $stig_id)) {
            $ref = $this->get_SV_Rule(null, $stig_id);
        } elseif (preg_match('/CVE\-\d{4}\-\d+/', $stig_id)) {
            $ref = [
                0 => $this->get_CVE($stig_id)
            ];
        } elseif (preg_match('/\d{4}\-[ABT]\-\d+/', $stig_id)) {
            $ref = [
                0 => $this->get_IAVM($stig_id)
            ];
        }

        if (is_null($ref) && $stig_id != 'No Reference') {
            $ref = $this->get_Stig($stig_id);
        }

        if (is_null($ref) && $vms_id != 'No Reference') {
            $ref = $this->get_GoldDisk($vms_id);
        }

        if (is_array($ref) && count($ref) && isset($ref[0])) {
            $ref = $ref[0];
        } else {
            // add a new checklist entry
            $pdi = new pdi(null, $cat_lvl, 'NOW', $short_title, $short_title);
            $pdi_id = $this->save_PDI($pdi);

            $stig = new stig($pdi_id, $stig_id, $short_title);
            $ref = $stig;
            $this->add_Stig($stig);

            $golddisk = new golddisk($pdi_id, $vms_id, $short_title);
            if ($vms_id != 'No Reference') {
                $this->save_GoldDisk($golddisk);
            }
        }

        if (is_array($tgts)) {
            $updated_finding = [];
            $new_finding = [];
            $x = 0;
            foreach ($tgts as $tgt) {
                switch (strtolower(str_replace('_', ' ', $finding_data[self::FIRST_ECHECKLIST_HOST_COL + $x]))) {
                    case 'not reviewed':
                    case 'not a finding':
                    case 'open':
                    case 'not applicable':
                    case 'no data':
                    case 'exception':
                    case 'false positive':
                        $status = $finding_data[self::FIRST_ECHECKLIST_HOST_COL + $x];
                        break;
                    default:
                        $status = 'Not Reviewed';
                }

                $current_finding = $this->get_Finding($tgt, $ref);
                if (is_array($current_finding) && count($current_finding) > 0) {
                    $current_finding = $current_finding[0];
                }

                $current_status = '';

                if ($current_finding != null) {
                    $current_status = $current_finding->get_Finding_Status_String();
                    // $current_source = $current_finding->get();

                    if ($current_status != $status) {
                        $current_notes = $current_finding->get_Notes();
                        if (! $current_notes) {
                            $current_finding->set_Notes($notes);
                        } else {
                            if ($notes && stristr($current_notes, $notes) === false) {
                                $current_finding->prepend_Notes($current_notes);
                            }
                        }

                        if (($current_status == 'Open' || $status == 'Open') && ($current_status == 'Not Applicable' || $current_status == 'Not a Finding' || $status == 'Not Applicable' || $status == 'Not a Finding')) {
                            $current_finding->set_Notes("OPEN CONFLICT: $current_status/$status\n$notes");

                            $current_finding->set_Change_ID(finding::TO_OPEN);
                        } elseif (($current_status == 'Not a Finding' || $current_status == 'Not Applicable') && ($status == 'Not a Finding' || $status == 'Not Applicable')) {
                            $current_finding->set_Notes("NF/NA CONFLICT: $current_status/$status\n$notes");

                            $current_finding->set_Change_ID(finding::TO_NF);
                        } else {
                            $current_finding->set_Change_ID(finding::NC);
                        }

                        $new_status = $current_finding->get_Deconflicted_Status($status);
                        $new_status_id = $current_finding->get_Finding_Status_ID($new_status);
                        $current_finding->set_Finding_Status($new_status_id);

                        $current_finding->set_Original_Source($scan->get_Source()
                            ->get_Name());
                        $current_finding->set_Finding_Iteration($current_finding->get_Finding_Iteration() + 1);
                        $current_finding->set_Scan_ID($scan->get_ID());
                        $current_finding->set_Category($cat_lvl);
                        $current_finding->set_IA_Controls($ia_controls);

                        $updated_finding[] = $current_finding;
                    } else {
                        $current_notes = $current_finding->get_Notes();
                        if (! $current_notes) {
                            $current_finding->set_Notes($notes);
                        } else {
                            if ($notes && stristr($current_notes, $notes) === false) {
                                $current_finding->set_Notes($current_notes . PHP_EOL . $notes);
                            }
                        }

                        $current_finding->set_Change_ID(finding::NC);
                        $current_finding->set_Original_Source($scan->get_Source()
                            ->get_Name());
                        $current_finding->set_Finding_Iteration($current_finding->get_Finding_Iteration() + 1);
                        $current_finding->set_Scan_ID($scan->get_ID());
                        $current_finding->set_Category($cat_lvl);
                        $current_finding->set_IA_Controls($ia_controls);

                        $updated_finding[] = $current_finding;
                    }
                } else {
                    $new = new finding($tgt->get_ID(), $ref->get_PDI_ID(), $scan->get_ID(), $status, $notes, 0, null, 1);
                    $new->set_Category($cat_lvl);
                    $new->set_IA_Controls($ia_controls);

                    $new_finding[] = $new;
                }

                if ($status == 'False Positive') {
                    $match = [];
                    if (preg_match("/\(FP\-([a-zA-Z \-]+)\)/i", $notes, $match)) {
                        $src = $match[1];
                        // $src = str_replace("_", " ", $match[1]);
                        $sql = "REPLACE INTO `false_positives` (`pdi_id`, `src_id`, `notes`) VALUES (" . $this->conn->real_escape_string($ref->get_PDI_ID()) . ", " . "(SELECT `id` FROM `sources` WHERE `name` = '" . $this->conn->real_escape_string($src) . "'), " . "'Common FP for $src')";

                        if (! $this->conn->real_query($sql)) {
                            error_log($this->conn->error);
                            Sagacity_Error::sql_handler($sql);
                        }

                        if (isset($cmd['debug'])) {
                            Sagacity_Error::err_handler("Added " . $ref->get_PDI_ID() . " to FP list for $src");
                        }
                    }
                }

                if ($status == 'Exception') {
                    $ste = $this->get_STE($tgt->get_STE_ID())[0];

                    $sql = "REPLACE INTO `exceptions` (`pdi_id`, `sys_id`, `notes`) VALUES (" . $this->conn->real_escape_string($ref->get_PDI_ID()) . ", " . $this->conn->real_escape_string($ste->get_System()
                        ->get_ID()) . ", " . "'')";

                    if (! $this->conn->real_query($sql)) {
                        error_log($this->conn->error);
                        Sagacity_Error::sql_handler($sql);
                    }

                    if (isset($cmd['debug'])) {
                        Sagacity_Error::err_handler("Added exception " . $ref->get_PDI_ID());
                    }
                }

                $x ++;
            }

            $notes = (isset($current_finding) && is_array($current_finding) && count($current_finding) ? $current_finding->get_Notes() . " " . $notes : $notes);

            if (isset($updated_finding) && is_array($updated_finding) && count($updated_finding) > 0) {
                /** @var finding $finding */
                foreach ($updated_finding as $finding) {
                    $this->help->update('findings', [
                        'scan_id' => $finding->get_Scan_ID(),
                        'findings_status_id' => $finding->get_Finding_Status(),
                        'notes' => $finding->get_Notes(),
                        'change_id' => $finding->get_Change_ID(),
                        'orig_src' => $finding->get_Original_Source(),
                        'finding_itr' => $finding->get_Finding_Iteration(),
                        'cat' => $finding->get_Category()
                    ], [
                        [
                            'field' => 'tgt_id',
                            'op' => '=',
                            'value' => $finding->get_Tgt_ID()
                        ],
                        [
                            'field' => 'pdi_id',
                            'op' => '=',
                            'value' => $finding->get_PDI_ID(),
                            'sql_op' => 'AND'
                        ]
                    ]);

                    if (! $this->help->execute()) {
                        $this->help->debug(E_ERROR);
                        return false;
                    }

                    $this->help->delete("finding_controls", null, [
                        [
                            'field' => 'tgt_id',
                            'op' => '=',
                            'value' => $finding->get_Tgt_ID()
                        ],
                        [
                            'field' => 'pdi_id',
                            'op' => '=',
                            'value' => $finding->get_PDI_ID(),
                            'sql_op' => 'AND'
                        ]
                    ]);
                    $this->help->execute();

                    $params = [];
                    foreach ($finding->get_IA_Controls() as $ia) {
                        $params[] = [
                            $finding->get_Tgt_ID(),
                            $finding->get_PDI_ID(),
                            $ia
                        ];
                    }
                    $this->help->extended_insert('finding_controls', ['tgt_id', 'pdi_id', 'ia_control'], $params, true);
                    $this->help->execute();
                }
            }

            if (isset($new_finding) && count($new_finding) > 0) {
                $finding_params = [];
                $finding_control_params = [];
                foreach ($new_finding as $finding) {
                    /** @var finding $finding */
                    $finding_params[] = [
                        $finding->get_Tgt_ID(),
                        $finding->get_PDI_ID(),
                        $finding->get_Scan_ID(),
                        $finding->get_Finding_Status(),
                        $finding->get_Category(),
                        $finding->get_Notes()
                    ];

                    foreach ($finding->get_IA_Controls() as $ia) {
                        $finding_control_params[] = [
                            $finding->get_Tgt_ID(),
                            $finding->get_PDI_ID(),
                            $ia
                        ];
                    }
                }

                if(is_array($finding_params) && count($finding_params)) {
                    $this->extended_insert('findings', ['tgt_id', 'pdi_id', 'scan_id', 'findings_status_id', 'cat', 'notes'], $finding_params, true);

                    if($this->help->execute()) {
                        $this->help->extended_insert('finding_controls', ['tgt_id', 'pdi_id', 'ia_control'], $finding_control_params, true);
                        $this->help->execute();
                    }
                }
            }

            return true;
        } else {
            $updated_finding = null;
            $new_finding = null;
            switch (strtolower(str_replace('_', ' ', $finding_data[self::FIRST_ECHECKLIST_HOST_COL]))) {
                case 'not reviewed':
                case 'not a finding':
                case 'open':
                case 'not applicable':
                case 'no data':
                case 'exception':
                case 'false positive':
                    $status = str_replace('_', ' ', $finding_data[self::FIRST_ECHECKLIST_HOST_COL]);
                    break;
                default:
                    $status = 'Not Reviewed';
            }

            $current_finding = $this->get_Finding($tgts, $ref);
            if (is_array($current_finding) && count($current_finding) > 0) {
                $current_finding = current($current_finding);
            }

            $current_status = '';

            if (is_a($current_finding, 'finding')) {
                $current_status = $current_finding->get_Finding_Status_String();

                if ($current_status != $status) {
                    $current_notes = $current_finding->get_Notes();
                    if (! $current_notes) {
                        $current_finding->set_Notes($notes);
                    } else {
                        if ($notes && stristr($current_notes, $notes) === false) {
                            $current_finding->set_Notes($current_notes . PHP_EOL . $notes);
                        }
                    }

                    if (($current_status == 'Open' || $status == 'Open') && ($current_status == 'Not Applicable' || $current_status == 'Not a Finding' || $status == 'Not Applicable' || $status == 'Not a Finding')) {
                        $current_finding->set_Notes("OPEN CONFLICT: $current_status/$status\n$notes");

                        $current_finding->set_Change_ID(finding::TO_OPEN);
                    } elseif (($current_status == 'Not a Finding' || $current_status == 'Not Applicable') && ($status == 'Not a Finding' || $status == 'Not Applicable')) {
                        $current_finding->set_Notes("NF/NA CONFLICT: $current_status/$status\n$notes");

                        $current_finding->set_Change_ID(finding::TO_NF);
                    } else {
                        $current_finding->set_Change_ID(finding::NC);
                    }

                    $new_status = $current_finding->get_Deconflicted_Status($status);
                    $new_status_id = $current_finding->get_Finding_Status_ID($new_status);
                    $current_finding->set_Finding_Status($new_status_id);

                    $current_finding->set_Original_Source($scan->get_Source()
                        ->get_Name());
                    $current_finding->set_Finding_Iteration($current_finding->get_Finding_Iteration() + 1);
                    $current_finding->set_Scan_ID($scan->get_ID());

                    $updated_finding = $current_finding;
                } else {
                    $current_notes = $current_finding->get_Notes();
                    if (! $current_notes) {
                        $current_finding->set_Notes($notes);
                    } else {
                        if ($notes && stristr($current_notes, $notes) === false) {
                            $current_finding->set_Notes($current_notes . PHP_EOL . $notes);
                        }
                    }

                    $current_finding->set_Change_ID(finding::NC);
                    $current_finding->set_Original_Source($scan->get_Source()
                        ->get_Name());
                    $current_finding->set_Finding_Iteration($current_finding->get_Finding_Iteration() + 1);
                    $current_finding->set_Scan_ID($scan->get_ID());

                    $updated_finding = $current_finding;
                }
            } else {
                $new_finding = new finding($tgts->get_ID(), $ref->get_PDI_ID(), $scan->get_ID(), $status, $notes, 0, null, 1);

                $new_finding->set_Category($cat_lvl);
                $new_finding->set_IA_Controls($ia_controls);
            }

            $notes = (isset($current_finding) && is_array($current_finding) && count($current_finding) ? $current_finding->get_Notes() . " " . $notes : $notes);

            if (isset($updated_finding) && ! is_null($updated_finding)) {
                $this->help->update("findings", [
                    'scan_id' => $updated_finding->get_Scan_ID(),
                    'findings_status_id' => $updated_finding->get_Finding_status(),
                    'notes' => $updated_finding->get_Notes(),
                    'change_id' => $updated_finding->get_Change_ID(),
                    'orig_src' => $updated_finding->get_Original_Source(),
                    'finding_itr' => $updated_finding->get_Finding_Iteration(),
                    'cat' => $updated_finding->get_Category()
                ], [
                    [
                        'field' => 'tgt_id',
                        'op' => '=',
                        'value' => $updated_finding->get_Tgt_ID()
                    ],
                    [
                        'field' => 'pdi_id',
                        'op' => '=',
                        'value' => $updated_finding->get_PDI_ID(),
                        'sql_op' => 'AND'
                    ]
                ]);

                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                    return false;
                }

                $this->help->delete("finding_controls", null, [
                    [
                        'field' => 'tgt_id',
                        'op' => '=',
                        'value' => $updated_finding->get_Tgt_ID()
                    ],
                    [
                        'field' => 'pdi_id',
                        'op' => '=',
                        'value' => $updated_finding->get_PDI_ID(),
                        'sql_op' => 'AND'
                    ]
                ]);
                $this->help->execute();

                $params = [];
                foreach ($updated_finding->get_IA_Controls() as $ia) {
                    $params[] = [
                        $updated_finding->get_Tgt_ID(),
                        $updated_finding->get_PDI_ID(),
                        $ia
                    ];
                }
                $this->help->extended_insert("finding_controls", ['tgt_id', 'pdi_id', 'ia_control'], $params, true);
                $this->help->execute();
            }

            if (isset($new_finding) && ! is_null($new_finding)) {
                $this->help->insert("findings", [
                    'tgt_id' => $new_finding->get_Tgt_ID(),
                    'pdi_id' => $new_finding->get_PDI_ID(),
                    'scan_id' => $new_finding->get_Scan_ID(),
                    'findings_status_id' => $new_finding->get_Finding_Status(),
                    'notes' => $new_finding->get_Notes(),
                    'cat' => $new_finding->get_Category()
                ], true);

                if(!$this->help->execute()) {
                    $this->help->debug(E_ERROR);
                    return false;
                }

                $params = [];
                foreach ($new_finding->get_IA_Controls() as $ia) {
                    $params[] = [
                        $new_finding->get_Tgt_ID(),
                        $new_finding->get_PDI_ID(),
                        $ia
                    ];
                }
                $this->help->extended_insert('finding_controls', ['tgt_id', 'pdi_id', 'ia_control'], $params, true);
                $this->help->execute();
            }

            return true;
        }
    }

    /**
     * Function to add findings to the database
     *
     * @param array:finding $updated_findings
     *            Array of findings to update
     * @param array:finding $added_findings
     *            Array of findings to add to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function add_Findings_By_Target($updated_findings, $added_findings)
    {
        $fields = [
            'pdi_id',
            'tgt_id',
            'scan_id',
            'findings_status_id',
            'notes',
            'cat'
        ];
        $ins_arr = [];

        if (is_array($added_findings) && count($added_findings) && is_a(current($added_findings), 'finding')) {
            $scan_id = current($added_findings)->get_Scan_ID();

            foreach ($added_findings as $finding) {
                /** @var finding $finding */
                $ins_arr[] = [
                    $finding->get_PDI_ID(),
                    $finding->get_Tgt_ID(),
                    $finding->get_Scan_ID(),
                    $finding->get_Finding_Status(),
                    $finding->get_Notes(),
                    $finding->get_Category()
                ];
            }

            if (is_array($ins_arr) && count($ins_arr)) {
                $this->help->extended_insert('findings', $fields, $ins_arr, true);

                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                }
            }

            $this->help->sql = "INSERT IGNORE INTO `finding_controls` (`tgt_id`, `pdi_id`, `ia_control`) " .
            "(SELECT f.`tgt_id`, f.`pdi_id`, " .
            "(SELECT CONCAT(ia.`type`, '-', ia.`type_id`) " .
            "FROM `ia_controls` ia " .
            "WHERE ia.`pdi_id` = f.`pdi_id`) " .
            "FROM `findings` f " .
            "WHERE f.`scan_id` = $scan_id)";
            $this->help->query_type = db_helper::INSERT;

            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
            }

            $this->help->delete("finding_controls", null, [
                [
                    'field' => 'ia_control',
                    'op' => '=',
                    'value' => ''
                ],
                [
                    'field' => 'ia_control',
                    'op' => '=',
                    'value' => '-',
                    'sql_op' => 'OR'
                ],
                [
                    'field' => 'ia_control',
                    'op' => IS,
                    'value' => null,
                    'sql_op' => 'OR'
                ]
            ]);
            $this->help->execute();
        }

        if (is_array($updated_findings) && count($updated_findings) && is_a(current($updated_findings), 'finding')) {
            $this->help->create_table("tmp_findings", true, [
                [
                    'field' => 'tgt_id',
                    'datatype' => 'int(11)'
                ],
                [
                    'field' => 'pdi_id',
                    'datatype' => 'int(11)'
                ],
                [
                    'field' => 'scan_id',
                    'datatype' => 'int(11)'
                ],
                [
                    'field' => 'findings_status_id',
                    'datatype' => 'int(11)'
                ],
                [
                    'field' => 'change_id',
                    'datatype' => 'int(11)'
                ],
                [
                    'field' => 'finding_itr',
                    'datatype' => 'int(5)'
                ],
                [
                    'field' => 'cat',
                    'datatype' => 'int(1)'
                ],
                [
                    'field' => 'notes',
                    'datatype' => 'text'
                ],
                [
                    'field' => 'orig_src',
                    'datatype' => 'varchar(10)'
                ]
            ]);
            $this->help->execute();
            $upd_arr = [];
            $update_fields = [
                'tgt_id',
                'pdi_id',
                'scan_id',
                'findings_status_id',
                'change_id',
                'finding_itr',
                'cat',
                'notes',
                'orig_src'
            ];
            foreach ($updated_findings as $finding) {
                /** @var finding $finding */
                $upd_arr[] = [
                    $finding->get_Tgt_ID(),
                    $finding->get_PDI_ID(),
                    $finding->get_Scan_ID(),
                    $finding->get_Finding_Status(),
                    $finding->get_Change_ID(),
                    $finding->get_Finding_Iteration(),
                    $finding->get_Category(),
                    $finding->get_Notes(),
                    $finding->get_Original_Source()
                ];
            }

            if (is_array($upd_arr) && count($upd_arr)) {
                $this->help->extended_insert("tmp_findings", $update_fields, $upd_arr, true);
                $this->help->execute();

                $this->help->extended_update('findings', 'tmp_findings', '`tgt_id`,`pdi_id`', $update_fields);

                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Function to update a finding status and notes
     *
     * @param finding $find
     *            The finding to update
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function update_Finding($find)
    {
        $this->help->replace("sagacity.findings", [
            'tgt_id' => $find->get_Tgt_ID(),
            'pdi_id' => $find->get_PDI_ID(),
            'scan_id' => $find->get_Scan_ID(),
            'findings_status_id' => $find->get_Finding_Status(),
            'notes' => $find->get_Notes(),
            'cat' => $find->get_Category()
        ]);

        if ($this->help->execute()) {
            $this->help->delete("sagacity.finding_controls", null, [
                [
                    'field' => 'tgt_id',
                    'op' => '=',
                    'value' => $find->get_Tgt_ID()
                ],
                [
                    'field' => 'pdi_id',
                    'op' => '=',
                    'value' => $find->get_PDI_ID(),
                    'sql_op' => 'AND'
                ]
            ]);

            $ia_arr = [];
            foreach ($find->get_IA_Controls() as $ia) {
                $ia_arr[] = [
                    $find->get_Tgt_ID(),
                    $find->get_PDI_ID(),
                    $ia
                ];
            }

            if (is_array($ia_arr) && count($ia_arr) && isset($ia_arr[0])) {
                $this->help->extended_insert("sagacity.finding_controls", [
                    'tgt_id',
                    'pdi_id',
                    'control_id'
                ], $ia_arr, true);
                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                    return false;
                }
            }
        } else {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Get count of open category I findings for a target
     *
     * @param integer $checklist_id
     *            Checklist ID to query for quantity
     * @param target $tgt
     *            Target to query
     *
     * @return integer Returns the number of findings that are Cat I and with a status of 'Open' for a specific host
     */
    public function get_Host_Open_Cat_1($checklist_id, $tgt)
    {
        $this->help->select_count("sagacity.pdi_catalog pdi", array(
            array(
                'field' => 'lu.checklist_id',
                'op' => '=',
                'value' => $checklist_id
            ),
            array(
                'field' => 'f.tgt_id',
                'op' => '=',
                'value' => $tgt->get_ID(),
                'sql_op' => 'AND'
            ),
            array(
                'field' => 'fs.status',
                'op' => '=',
                'value' => 'Open',
                'sql_op' => 'AND'
            ),
            array(
                'field' => 'pdi.cat',
                'op' => '=',
                'value' => 1,
                'sql_op' => 'AND'
            )
        ), array(
            'table_joins' => array(
                "JOIN sagacity.pdi_checklist_lookup lu ON lu.pdi_id=pdi.id",
                "JOIN sagacity.findings f ON f.pdi_id=pdi.id",
                "LEFT JOIN sagacity.stigs s ON s.pdi_id=pdi.id",
                "LEFT JOIN sagacity.findings_status fs ON fs.id=f.findings_status_id"
            )
        ));

        return $this->help->execute();
    }

    /**
     * Get count of not reviewed findings for a target
     *
     * @param integer $checklist_id
     *            Checklist ID to query for quantity
     * @param target $tgt
     *            Target to query
     *
     * @return integer Returns the number of findings with a status of 'Not Reviewed' for a specific host
     */
    public function get_Host_Not_Reviewed($checklist_id, $tgt)
    {
        $this->help->select_count("sagacity.pdi_catalog pdi", array(
            array(
                'field' => 'lu.checklist_id',
                'op' => '=',
                'value' => $checklist_id
            ),
            array(
                'field' => 'f.tgt_id',
                'op' => '=',
                'value' => $tgt->get_ID(),
                'sql_op' => 'AND'
            ),
            array(
                'field' => 'fs.status',
                'op' => '=',
                'value' => 'Not Reviewed',
                'sql_op' => 'AND'
            )
        ), array(
            'table_joins' => array(
                "JOIN sagacity.pdi_checklist_lookup lu ON lu.pdi_id=pdi.id",
                "JOIN sagacity.findings f ON f.pdi_id=pdi.id",
                "LEFT JOIN sagacity.stigs s ON s.pdi_id=pdi.id",
                "LEFT JOIN sagacity.findings_status fs ON fs.id=f.findings_status_id"
            )
        ));

        return $this->help->execute();
    }

    // }}}
    // {{{ GOLDDISK CLASS FUNCTIONS
    /**
     * Get GoldDisk data
     *
     * @param string $str_VMS_ID
     *            [optional]
     *            The VMS id of the golddisk object (default null)
     *
     * @return array:golddisk |NULL
     *         Returns an array of golddisk objects, or null if none found
     */
    public function get_GoldDisk($str_VMS_ID = null)
    {
        $ret = [];
        $where = [];

        if ($str_VMS_ID != null) {
            $where[] = array(
                'field' => 'vms_id',
                'op' => '=',
                'value' => $str_VMS_ID
            );
        }

        $this->help->select("sagacity.golddisk", null, $where);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['pdi_id'])) {
            $rows = array(
                0 => $rows
            );
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = new golddisk($row['pdi_id'], $row['vms_id'], $row['short_title']);
            }
        }

        return $ret;
    }

    /**
     * Function for retrieving a VMS using the PDI
     *
     * @param integer $pdi_id
     *            The PDI ID of the golddisk to grab
     *
     * @return array:golddisk |NULL
     *         Returns an array of golddisk, or null if none found
     */
    public function get_GoldDisk_By_PDI($pdi_id)
    {
        $ret = [];
        $this->help->select("golddisk", null, [
            [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $pdi_id
            ]
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['pdi_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = new golddisk($row['pdi_id'], $row['vms_id'], $row['short_title']);
            }
        } else {
            $this->help->debug(E_ERROR);
        }

        return $ret;
    }

    /**
     * Function to add GoldDisk to database
     *
     * @param golddisk $new_GoldDisk
     *            The golddisk object to add to database
     *
     * @return boolean Returns TRUE if successful, otherwise false
     */
    public function save_GoldDisk($new_GoldDisk)
    {
        $this->help->insert("sagacity.golddisk", array(
            'pdi_id' => $new_GoldDisk->get_PDI_ID(),
            'vms_id' => $new_GoldDisk->get_ID(),
            'short_title' => $new_GoldDisk->get_Short_Title()
        ), true);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }
        return true;
    }

    // }}}
    // {{{ IA_CONTROL CLASS FUNCTIONS
    /**
     * Function to get IA control from DB
     *
     * @param ia_control $ia
     *            IA Control to retrieve from the database
     *
     * @return ia_control|NULL Returns IA_Control object, or null if none found
     */
    public function get_IA_Controls($ia)
    {
        $sql = "SELECT `pdi_id`, `type`, `type_id` " . "FROM `sagacity`.`ia_controls` " . "WHERE " . "`pdi_id` = " . $this->conn->real_escape_string($ia->get_PDI_ID()) . " AND " . "`type` = '" . $this->conn->real_escape_string($ia->get_Type()) . "' AND " . "`type_id` = " . $this->conn->real_escape_string($ia->get_Type_ID());

        $res = $this->conn->query($sql);

        if ($res->num_rows > 0) {
            $row = $res->fetch_assoc();

            return new ia_control($row['pdi_id'], $row['type'], $row['type_id']);
        }

        return null;
    }

    /**
     * Function for retrieving all the IA controls by mac and classification
     *
     * @param system $sys
     *
     * @return array:ia_control
     */
    public function get_IA_Controls_By_Mac_Class($sys)
    {
        $class = 'cl';
        if ($sys->get_Classification() == 'Public') {
            $class = 'pub';
        } elseif ($sys->get_Classification() == 'Sensitive') {
            $class = 'sen';
        }
        $ret = [];
        $sql = "SELECT `proc_control` " . "FROM `sagacity`.`proc_level_type` " . "WHERE " . "`level` = " . $sys->get_MAC() . " AND " . "`class` = '$class'";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $ret[] = new ia_control(null, explode('-', $row['proc_control'])[0], explode('-', $row['proc_control'])[1]);
            }
        } else {
            error_log($this->conn->error);
            Sagacity_Error::sql_handler($sql);
        }

        return $ret;
    }

    /**
     * Function for retrieving IA Controls by PDI
     *
     * @param integer $pdi_id
     *            PDI ID used to query
     *
     * @return array:ia_control |NULL
     *         Returns array of ia_controls associated with a specific PDI, or null if none found
     */
    public function get_IA_Controls_By_PDI($pdi_id)
    {
        $sql = "SELECT " . "`pdi_id`, `type`, `type_id` " . "FROM `sagacity`.`ia_controls` " . "WHERE `pdi_id` = " . $this->conn->real_escape_string($pdi_id);

        if ($res = $this->conn->query($sql)) {
            $ret = [];

            while ($row = $res->fetch_assoc()) {
                $ret[] = new ia_control($row['pdi_id'], $row['type'], $row['type_id']);
            }

            return $ret;
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return null;
    }

    /**
     * Function to get the icon that represents the IA control status
     *
     * @param ste $ste
     * @param proc_ia_controls $ctrl
     *
     * @return string
     */
    public function get_IA_Control_Icon($ste, $ctrl)
    {
        $cats = $this->get_STE_Cat_List($ste->get_ID());
        $total = 0;

        foreach ($cats as $cat) {
            $total += $this->get_Finding_Count_By_Status($cat->get_ID(), "Open", null, $ctrl);
            $total += $this->get_Finding_Count_By_Status($cat->get_ID(), "Exception", null, $ctrl);
        }

        if ($total) {
            return "error.png";
        }

        if (false) {
            $ctrl = new proc_ia_controls();
        }
        if (empty($ctrl->finding->vul_desc)) {
            return "exclamation.png";
        } elseif (empty($ctrl->finding->mitigations)) {
            return "exclamation.png";
        }

        return "Under_construction.svg";
    }

    /**
     * Update an IA control
     *
     * @param ia_control|array:ia_control $ia_Controls
     *            Array of IA Controls to update
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_IA_Control($ia_Controls)
    {
        $params = [];

        if (is_array($ia_Controls) && count($ia_Controls) && isset($ia_Controls[0]) && is_a($ia_Controls[0], 'ia_control')) {
            foreach ($ia_Controls as $ia) {
                $params[] = array(
                    $ia->get_PDI_ID(),
                    $ia->get_Type(),
                    $ia->get_Type_ID()
                );
            }
        } elseif (is_a($ia_Controls, 'ia_control')) {
            $params[] = array(
                $ia_Controls->get_PDI_ID(),
                $ia_Controls->get_Type(),
                $ia_Controls->get_Type_ID()
            );
        } else {
            return false;
        }

        $this->help->extended_replace("sagacity.ia_controls", array(
            'pdi_id',
            'type',
            'type_id'
        ), $params);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ IAVM CLASS FUNCTIONS
    /**
     * Function for retrieving an IAVM
     *
     * @param integer|string $iavm_ID
     *            The IAVM ID to look for
     *
     * @return iavm|NULL Returns IAVM object, otherwise null if none found
     */
    public function get_IAVM($iavm_ID)
    {
        $sql = "SELECT " . "iavm.`noticeId`, iavm.`pdi_id`, iavm.`xmlUrl`, iavm.`htmlUrl`, iavm.`iavmNoticeNumber`, iavm.`title`, " . "iavm.`type`, iavm.`state`, iavm.`lastUpdated`, iavm.`releaseDate`, iavm.`supersedes`, " . "iavm.`executiveSummary`, iavm.`fixAction`, iavm.`note`, iavm.`vulnAppsSysAndCntrmsrs`, " . "iavm.`stigFindingSeverity`, iavm.`knownExploits`, iavm.`file_name` " . "FROM `sagacity`.`iavm_notices` iavm";

        if (is_numeric($iavm_ID)) {
            $sql .= " WHERE iavm.`noticeId` = " . $this->conn->real_escape_string($iavm_ID);
        } else {
            $sql .= " WHERE iavm.`iavmNoticeNumber` = '" . $this->conn->real_escape_string($iavm_ID) . "'";
        }

        if ($res = $this->conn->query($sql)) {
            if (! $res->num_rows) {
                return null;
            }
            $notice_row = $res->fetch_assoc();
            $noticeId = $notice_row['noticeId'];

            $iavm = new iavm($notice_row['noticeId'], $notice_row['pdi_id'], $notice_row['xmlUrl'], $notice_row['htmlUrl'], $notice_row['iavmNoticeNumber'], $notice_row['title'], $notice_row['type'], $notice_row['state'], $notice_row['lastUpdated'], $notice_row['releaseDate'], $notice_row['supersedes'], $notice_row['executiveSummary'], $notice_row['fixAction'], $notice_row['note'], $notice_row['vulnAppsSysAndCntrmsrs'], $notice_row['stigFindingSeverity'], $notice_row['knownExploits']);

            $sql = "SELECT `cve_id` FROM `sagacity`.`iavm_to_cve` WHERE `noticeId` = " . $notice_row['noticeId'];

            if ($res2 = $this->conn->query($sql)) {
                if ($res2->num_rows) {
                    while ($row2 = $res2->fetch_assoc()) {
                        $iavm->add_CVE($row2['cve_id']);
                    }
                }
            }

            $sql = "SELECT `id`, `title`, `url` FROM `sagacity`.`iavm_references` " . "WHERE `iavm_notice_id` = " . $this->conn->real_escape_string($noticeId);

            if ($res2 = $this->conn->query($sql)) {
                if ($res2->num_rows) {
                    while ($ref_row = $res2->fetch_assoc()) {
                        $iavm->add_Reference(new iavm_reference($ref_row['id'], $ref_row['title'], $ref_row['url']));
                    }
                }
            } else {
                Sagacity_Error::sql_handler($sql);
                error_log($this->conn->error);
            }

            $sql = "SELECT `id`, `details` FROM `sagacity`.`iavm_tech_overview` " . "WHERE `iavm_notice_id` = " . $this->conn->real_escape_string($noticeId);

            if ($res2 = $this->conn->query($sql)) {
                if ($res2->num_rows) {
                    $to_row = $res2->fetch_assoc();
                    $to = new iavm_tech_overview($to_row['id'], $to_row['details']);
                    $iavm->set_Tech_Overview($to);
                }
            } else {
                Sagacity_Error::sql_handler($sql);
                error_log($this->conn->error);
            }

            $sql = "SELECT `id`, `type`, `title`, `url` FROM sagacity.iavm_patches " . "WHERE `iavm_notice_id` = " . $this->conn->real_escape_string($noticeId);

            if ($res2 = $this->conn->query($sql)) {
                if ($res2->num_rows) {
                    while ($patch_row = $res2->fetch_assoc()) {
                        $iavm->add_Patch(new iavm_patch($patch_row['id'], $patch_row['type'], $patch_row['title'], $patch_row['url']));
                    }
                }
            } else {
                Sagacity_Error::sql_handler($sql);
                error_log($this->conn->error);
            }

            $sql = "SELECT `header`, `body` FROM `sagacity`.`iavm_mitigations` " . "WHERE `iavm_notice_id` = " . $this->conn->real_escape_string($noticeId);

            if ($res2 = $this->conn->query($sql)) {
                if ($res2->num_rows) {
                    $mit_row = $res2->fetch_assoc();

                    $iavm->set_Mitigation(new iavm_mitigation($mit_row['header'], $mit_row['body']));
                }
            } else {
                Sagacity_Error::sql_handler($sql);
                error_log($this->conn->error);
            }

            $sql = "SELECT `bid` FROM `sagacity`.`iavm_bids` " . "WHERE `iavm_notice_id` = " . $this->conn->real_escape_string($noticeId);

            if ($res2 = $this->conn->query($sql)) {
                if ($res2->num_rows) {
                    while ($bid_row = $res2->fetch_assoc()) {
                        $iavm->add_Bid(new iavm_bid($bid_row['bid']));
                    }
                }
            }

            return $iavm;
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return null;
    }

    /**
     * Get IAVM from external data (reference or patch)
     *
     * @param string $ext
     *            The external data to search for
     *
     * @return iavm|NULL Returns an iavm object if any are found, otherwise NULL
     */
    public function get_IAVM_From_External($ext)
    {
        $sql = "SELECT `iavm_notice_id` FROM `sagacity`.`iavm_references` " . "WHERE `title` LIKE '%" . $this->conn->real_escape_string($ext) . "%' OR " . "`url` LIKE '%" . $this->conn->real_escape_string($ext) . "%' " . "GROUP BY `iavm_notice_id` " . "ORDER BY `iavm_notice_id` DESC";

        if ($res = $this->conn->query($sql)) {
            if ($res->num_rows) {
                $row = $res->fetch_assoc();
                $iavm = $this->get_IAVM($row['iavm_notice_id']);
                return $iavm;
            }
        } else {
            Sagacity_Error::sql_handler($sql);
        }

        $sql = "SELECT `iavm_notice_id` FROM `sagacity`.`iavm_patches` " . "WHERE `title` LIKE '%" . $this->conn->real_escape_string($ext) . "%' OR " . "`url` LIKE '%" . $this->conn->real_escape_string($ext) . "%' " . "GROUP BY `iavm_notice_id` " . "ORDER BY `iavm_notice_id` DESC";

        if ($res = $this->conn->query($sql)) {
            if ($res->num_rows) {
                $row = $res->fetch_assoc();
                $iavm = $this->get_IAVM($row['iavm_notice_id']);
                return $iavm;
            }
        } else {
            Sagacity_Error::sql_handler($sql);
        }

        return null;
    }

    /**
     * Method to save IAVM BIDs
     *
     * @param iavm $iavm
     */
    public function save_Iavm_Bids($iavm)
    {
        $params = [];
        if (is_array($iavm->get_Bids()) && count($iavm->get_Bids())) {
            foreach ($iavm->get_Bids() as $bid) {
                $params[] = [
                    $iavm->get_Notice_ID(),
                    $bid
                ];
            }
        }

        if (count($params)) {
            $this->help->extended_replace('iavm_bids', [
                'iavm_notice_id',
                'bid'
            ], $params);
            $this->help->execute();
        }
    }

    /**
     * Method to save IAVM mitigations
     *
     * @param iavm $iavm
     */
    public function save_Iavm_Mitigation($iavm)
    {
        if ($iavm->get_Mitigation()) {
            $this->help->replace("iavm_mitiagations", [
                'iavm_notice_id' => $iavm->get_Notice_ID(),
                'header' => $iavm->get_Mitigation()
                    ->get_Header(),
                'body' => $iavm->get_Mitigation()
                    ->get_Text()
            ]);

            $this->help->execute();
        }
    }

    /**
     * Method to save IAVM patches
     *
     * @param iavm $iavm
     */
    public function save_Iavm_Patches($iavm)
    {
        $params = [];
        if (is_array($iavm->get_Patches()) && count($iavm->get_Patches())) {
            foreach ($iavm->get_Patches() as $patch) {
                $params[] = [
                    $iavm->get_Notice_ID(),
                    $patch->get_Type(),
                    $patch->get_Title(),
                    $patch->get_URL()
                ];
            }
        }

        if (count($params)) {
            $this->help->extended_replace("iavm_patches", [
                'iavm_notice_id',
                'type',
                'title',
                'url'
            ], $params);

            $this->help->execute();
        }
    }

    /**
     * Method to save IAVM references
     *
     * @param iavm $iavm
     */
    public function save_Iavm_References($iavm)
    {
        $params = [];
        if (is_array($iavm->get_References()) && count($iavm->get_References())) {
            foreach ($iavm->get_References() as $ref) {
                $params[] = [
                    $iavm->get_Notice_ID(),
                    $ref->get_Title(),
                    $ref->get_URL()
                ];
            }
        }

        if (count($params)) {
            $this->help->extended_replace("iavm_references", [
                'iavm_notice_id',
                'title',
                'url'
            ], $params);

            $this->help->execute();
        }
    }

    /**
     * Method to save IAVM tech overview data
     *
     * @param iavm $iavm
     */
    public function save_Iavm_Tech_Overview($iavm)
    {
        if ($iavm->get_Tech_Overview()) {
            $this->help->replace("iavm_tech_overview", [
                'iavm_notice_id' => $iavm->get_Notice_ID(),
                'details' => $iavm->get_Tech_Overview()
                    ->get_Details()
            ]);

            $this->help->execute();
        }
    }

    /**
     * Method to save IAVM-to-CVE references
     *
     * @param iavm $iavm
     */
    public function save_Iavm_Cves($iavm)
    {
        $params = [];
        if (is_array($iavm->get_CVE()) && count($iavm->get_CVE())) {
            foreach ($iavm->get_CVE() as $cve) {
                $params[] = [
                    $iavm->get_Notice_ID(),
                    $cve
                ];
            }
        }

        if (count($params)) {
            $this->help->extended_replace("iavm_to_cve", [
                'noticeId',
                'cve_id'
            ], $params);
            $this->help->execute();
        }
    }

    /**
     * Function to save IAVMs
     *
     * @param iavm $iavm_in
     *            The IAVM to save
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_IAVM($iavm_in)
    {
        // check to see if the IAVM already exists
        $db_iavm = $this->get_IAVM($iavm_in->get_Notice_ID());

        if (is_null($db_iavm)) {
            $this->help->insert('iavm_notices', [
                'noticeId' => $iavm_in->get_Notice_ID(),
                'pdi_id' => $iavm_in->get_PDI_ID(),
                'xmlUrl' => $iavm_in->get_XML_URL(),
                'htmlUrl' => $iavm_in->get_HTML_URL(),
                'iavmNoticeNumber' => $iavm_in->get_Notice_Number(),
                'title' => $iavm_in->get_Title(),
                'type' => $iavm_in->get_Type(),
                'state' => $iavm_in->get_State(),
                'lastUpdate' => $iavm_in->get_Last_Updated_Date(),
                'releaseDate' => $iavm_in->get_Release_Date_Date(),
                'supersedes' => $iavm_in->get_Supersedes(),
                'executiveSummary' => $iavm_in->get_Executive_Summary(),
                'fixAction' => $iavm_in->get_Fix_Action(),
                'note' => $iavm_in->get_Notes(),
                'vulnAppsSysAndCntrmsrs' => $iavm_in->get_Vuln_Apps(),
                'stigFindingSeverity' => $iavm_in->get_Stig_Severity(),
                'knownExploits' => $iavm_in->get_Known_Exploits()
            ]);
        } else {
            $this->help->update("iavm_notices", [
                'type' => $iavm_in->get_Type(),
                'state' => $iavm_in->get_State(),
                'lastUpdated' => $iavm_in->get_Last_Updated_Date(),
                'supersedes' => $iavm_in->get_Supersedes(),
                'executiveSummary' => $iavm_in->get_Executive_Summary(),
                'fixAction' => $iavm_in->get_Fix_Action(),
                'knownExploits' => $iavm_in->get_Known_Exploits(),
                'note' => $iavm_in->get_Notes(),
                'vulnAppsSysAndCntrmsrs' => $iavm_in->get_Vuln_Apps()
            ], [
                [
                    'field' => 'noticeId',
                    'op' => '=',
                    'value' => $iavm_in->get_Notice_ID()
                ]
            ]);
        }

        if ($this->help->execute()) {
            $this->save_Iavm_Bids($iavm_in);
            $this->save_Iavm_Mitigation($iavm_in);
            $this->save_Iavm_Patches($iavm_in);
            $this->save_Iavm_References($iavm_in);
            $this->save_Iavm_Tech_Overview($iavm_in);
            $this->save_Iavm_Cves($iavm_in);
        }
    }

    // }}}
    // {{{ INTERFACES CLASS FUNCTIONS
    /**
     * Get all interfaces for a target
     *
     * @param integer $tgtID
     *            Target ID to get interface information for
     *
     * @return array:interfaces|NULL Returns array of interfaces (with ports), or NULL if none found
     */
    public function get_Interfaces($tgtID)
    {
        $ret = [];
        if (! $tgtID) {
            return [];
        }

        $this->help->select("sagacity.interfaces", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgtID
            ],
            [
                'field' => 'ipv4',
                'op' => '!=',
                'value' => '',
                'sql_op' => 'AND'
            ],
            [
                'field' => 'ipv4',
                'op' => IS_NOT,
                'value' => null,
                'sql_op' => 'AND'
            ]
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $int = new interfaces($row['id'], $row['tgt_id'], $row['name'], $row['ipv4'], $row['ipv6'], $row['hostname'], $row['fqdn'], $row['description']);
                $int->set_MAC($row['mac']);

                $this->help->select("sagacity.get_ports", null, [
                    [
                        'field' => 'int_id',
                        'op' => '=',
                        'value' => $row['id']
                    ]
                ]);

                $rows2 = $this->help->execute();
                if (is_array($rows2) && count($rows2) && isset($rows2['id'])) {
                    $rows2 = [
                        0 => $rows2
                    ];
                }

                if (is_array($rows2) && count($rows2) && isset($rows2[0])) {
                    foreach ($rows2 as $p) {
                        if ($p['proto'] == 'tcp') {
                            $port = new tcp_ports($p['id'], $p['port'], $p['name'], $p['banner'], $p['notes']);
                            $int->add_TCP_Ports($port);
                        } else {
                            $port = new udp_ports($p['id'], $p['port'], $p['name'], $p['banner'], $p['notes']);
                            $int->add_UDP_Ports($port);
                        }
                    }
                }

                if ($row['ipv6']) {
                    $ret[$row['ipv6']] = $int;
                } else {
                    $ret[$row['ipv4']] = $int;
                }
            }
        }

        return $ret;
    }

    /**
     * Function to get an interface object using the IP address
     *
     * @param integer $tgt_id
     * @param string $ip
     *
     * @return NULL|interfaces
     */
    public function get_Interface_By_IP($tgt_id, $ip)
    {
        $this->help->select("sagacity.interfaces", null, array(
            array(
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ),
            array(
                'field' => 'ipv4',
                'op' => '=',
                'value' => $ip,
                'sql_op' => 'AND',
                'open-paren' => true
            ),
            array(
                'field' => 'ipv6',
                'op' => '=',
                'value' => $ip,
                'sql_op' => 'OR',
                'close-paren' => true
            )
        ));

        $row = $this->help->execute();
        if (is_null($row)) {
            return null;
        }
        $int = new interfaces($row['id'], $row['tgt_id'], $row['name'], $row['ipv4'], $row['ipv6'], $row['hostname'], $row['fqdn'], $row['description']);

        $this->help->select("sagacity.ports_proto_services pps", array(
            'pps.id',
            'pps.port',
            'pps.proto',
            "IF(ppsl.name != pps.IANA_Name, ppsl.name, pps.IANA_Name) AS 'name'",
            "IF(ppsl.banner != pps.banner, ppsl.banner, pps.banner) AS 'banner'",
            "IF(ppsl.notes != pps.notes, ppsl.notes, pps.notes) AS 'notes'"
        ), array(
            array(
                'field' => 'ppsl.int_id',
                'op' => '=',
                'value' => $row['id']
            ),
            array(
                'field' => 'pps.id',
                'op' => IN,
                'value' => "(SELECT pps_id FROM sagacity.pps_list WHERE int_id={$row['id']})",
                'sql_op' => 'AND'
            )
        ), array(
            'table_joins' => array(
                "LEFT JOIN sagacity.pps_list ppsl ON ppsl.pps_id=pps.id"
            )
        ));

        $rows2 = $this->help->execute();
        if (is_array($rows2) && count($rows2) && isset($rows2['id'])) {
            $rows2 = array(
                0 => $rows2
            );
        }

        if (is_array($rows2) && count($rows2) && isset($rows2[0])) {
            foreach ($rows2 as $port) {
                $class = "{$port['proto']}_ports";
                $method = "add_" . strtoupper($port['proto']) . "_Ports";
                $port = new $class($port['id'], $port['port'], $port['name'], $port['banner'], $port['notes']);
                $int->$method($port);
            }
        }

        return $int;
    }

    /**
     * Return the last ID of the last interface in the database
     *
     * @return integer Returns the ID of the last interface that was inserted
     */
    public function get_Last_Interface_ID()
    {
        $this->help->select("sagacity.interfaces", array(
            'id'
        ), [], array(
            'order' => 'id DESC',
            'limit' => 1
        ));

        $row = $this->help->execute();
        if (isset($row['id']) && $row['id'])
            return $row['id'];
        else
            return 0;
    }

    /**
     * Save an interface
     *
     * @param array|interfaces $req
     *            Associative array of data to insert into database
     * @param string $action
     *            [optional]
     *            String representing the action to be taken ('insert','update', defaulted to 'insert')
     * @param integer $tgt_id
     *            [optional]
     *            Integer that the interface info is going to be save to (defaulted to 0)
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Interface($req, $action = 'insert')
    {
        if ($action == 'insert') {
            if (is_array($req)) {
                $first = array_shift($req);
                if (! is_a($first, 'interfaces')) {
                    return false;
                }
                $req[$first->get_IPv4()] = $first;
                foreach ($req as $int) {
                    $this->help->insert("sagacity.interfaces", array(
                        'tgt_id' => $int->get_TGT_ID(),
                        'ipv4' => $int->get_IPv4(),
                        'ipv6' => $int->get_IPv6(),
                        'hostname' => $int->get_Hostname(),
                        'fqdn' => $int->get_FQDN(),
                        'description' => $int->get_Description(),
                        'mac' => $int->get_MAC()
                    ), true);

                    if (! ($int_id = $this->help->execute())) {
                        $this->help->debug(E_ERROR);
                        return false;
                    }

                    $int->set_ID($int_id);
                    $ports = [];

                    if (is_array($int->get_TCP_Ports()) && count($int->get_TCP_Ports())) {
                        foreach ($int->get_TCP_Ports() as $tcp) {
                            $ports[] = array(
                                $int->get_ID(),
                                $tcp->get_ID(),
                                $tcp->get_Banner(),
                                $tcp->get_Notes()
                            );
                        }
                    }

                    if (is_array($int->get_UDP_Ports()) && count($int->get_UDP_Ports())) {
                        foreach ($int->get_UDP_Ports() as $udp) {
                            $ports[] = array(
                                $int->get_ID(),
                                $udp->get_ID(),
                                $udp->get_Banner(),
                                $udp->get_Notes()
                            );
                        }
                    }

                    if (count($ports)) {
                        $this->help->extended_insert("pps_list", array(
                            'int_id',
                            'pps_id',
                            'banner',
                            'notes'
                        ), $ports, true);
                        if (! $this->help->execute()) {
                            $this->help->debug(E_WARNING);
                        }
                    }
                }
            } elseif (is_a($req, 'interfaces')) {
                $this->help->insert("interfaces", array(
                    'tgt_id' => $req->get_TGT_ID(),
                    'ipv4' => $req->get_IPv4(),
                    'ipv6' => $req->get_IPv6(),
                    'hostname' => $req->get_Hostname(),
                    'fqdn' => $req->get_FQDN(),
                    'description' => $req->get_Description(),
                    'mac' => $req->get_MAC()
                ), true);

                if (! ($int_id = $this->help->execute())) {
                    $this->help->debug(E_ERROR);
                    return false;
                }

                $req->set_ID($int_id);
                $ports = [];

                if (is_array($req->get_TCP_Ports()) && count($req->get_TCP_Ports())) {
                    foreach ($req->get_TCP_Ports() as $tcp) {
                        $ports[] = array(
                            $int->get_ID(),
                            $tcp->get_ID(),
                            $tcp->get_Banner(),
                            $tcp->get_Notes()
                        );
                    }
                }

                if (is_array($req->get_UDP_Ports()) && count($req->get_UDP_Ports())) {
                    foreach ($req->get_UDP_Ports() as $udp) {
                        $ports[] = array(
                            $int->get_ID(),
                            $udp->get_ID(),
                            $udp->get_Banner(),
                            $udp->get_Notes()
                        );
                    }
                }

                if (count($ports)) {
                    $this->help->extended_insert("sagacity.pps_list", array(
                        'int_id',
                        'pps_id',
                        'banner',
                        'notes'
                    ), $ports, true);
                    if (! $this->help->execute()) {
                        $this->help->debug(E_WARNING);
                    }
                }
            } else {
                $this->help->insert("interfaces", array(
                    'tgt_id' => $req['tgt_id'],
                    'ipv4' => $req['ipv4'],
                    'hostname' => (isset($req['hostname']) ? $req['hostname'] : $req['ipv4']),
                    'fadn' => (isset($req['fqdn']) ? $req['fqdn'] : $req['fqdn'])
                ), true);

                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                    return false;
                }
            }
        } else {
            if (isset($req['ip']) && $req['ip'] != null) {
                foreach ($req['ip'] as $int_id => $val) {
                    if (isset($req['new'][$int_id])) {
                        $this->help->insert("sagacity.interfaces", [
                            'tgt_id' => $req['tgt'],
                            'ipv4' => $req['ip'][$int_id],
                            'hostname' => $req['hostname'][$int_id],
                            'fqdn' => $req['fqdn'][$int_id],
                            'name' => $req['name'][$int_id],
                            'description' => $req['description'][$int_id]
                        ], true);

                        if (! $this->help->execute()) {
                            $this->help->debug(E_ERROR);
                            return false;
                        }
                    } elseif ($val != 'DELETE') {
                        $this->help->update("sagacity.interfaces", [
                            'name' => $req['name'][$int_id],
                            'ipv4' => $val,
                            'hostname' => $req['hostname'][$int_id],
                            'fqdn' => $req['fqdn'][$int_id],
                            'description' => $req['description'][$int_id]
                        ], [
                            [
                                'field' => 'id',
                                'op' => '=',
                                'value' => $int_id
                            ]
                        ]);

                        if ($this->help->execute()) {
                            $tcp_ports = isset($req['tcp_port'][$int_id]) ? $req['tcp_port'][$int_id] : [];
                            $udp_ports = isset($req['udp_port'][$int_id]) ? $req['udp_port'][$int_id] : [];

                            $ports = [];

                            if (is_array($tcp_ports) && count($tcp_ports) > 0) {
                                foreach ($tcp_ports as $port_id => $val2) {
                                    $ports[] = [
                                        $int_id,
                                        $port_id,
                                        $req['iana_name'][$int_id][$port_id],
                                        $req['banner'][$int_id][$port_id],
                                        $req['notes'][$int_id][$port_id]
                                    ];
                                }
                            }

                            if (is_array($udp_ports) && count($udp_ports) > 0) {
                                foreach ($udp_ports as $int_id => $val2) {
                                    $ports[] = [
                                        $int_id,
                                        $port_id,
                                        $req['iana_name'][$int_id][$port_id],
                                        $req['banner'][$int_id][$port_id],
                                        $req['notes'][$int_id][$port_id]
                                    ];
                                }
                            }

                            if (count($ports)) {
                                $this->help->extended_insert("pps_list", [
                                    'int_id',
                                    'pps_id',
                                    'name',
                                    'banner',
                                    'notes'
                                ], $ports, true);
                                if (! $this->help->execute()) {
                                    $this->help->debug(E_WARNING);
                                }
                            }
                        } else {
                            $this->help->debug(E_ERROR);
                            return false;
                        }
                    } else {
                        $this->help->delete("sagacity.pps_list", null, array(
                            array(
                                'field' => 'int_id',
                                'op' => '=',
                                'value' => $int_id
                            )
                        ));
                        $this->help->execute();
                        $this->help->delete("sagacity.interfaces", null, array(
                            array(
                                'field' => 'id',
                                'op' => '=',
                                'value' => $int_id
                            )
                        ));
                        $this->help->execute();
                    }
                }
            }
        }
        return true;
    }

    /**
     * Function to delete an target interface from the database
     *
     * @param int $id
     *            The ID of the interface to be deleted
     *
     * @return boolean Returns TRUE if interface successfully deleted, otherwise FALSE
     */
    public function delete_Interface($id)
    {
        // delete all associated ports
        $this->help->delete("sagacity.pps_list", null, [
            [
                'field' => 'int_id',
                'op' => '=',
                'value' => $id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
            return false;
        }

        // delete the interface itself
        $this->help->delete("sagacity.interfaces", null, [
            [
                'field' => 'id',
                'op' => '=',
                'value' => $id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
            return false;
        }

        return true;
    }

    // {{{ Ports
    /**
     * Save the port to the database
     *
     * @param interfaces $int
     *            Interface to tie the ports to
     * @param array:tcp_ports|array:udp_ports $ports
     *            Array of tcp and udp ports that are to be saved
     * @param string $action
     *            [optional]
     *            Whether or not the ports are to be updated or inserted (defaulted 'insert')
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Ports($int, $ports, $action = 'insert')
    {
        $ret = true;
        $ins_sql = 'REPLACE INTO `sagacity`.`pps_list` (`int_id`,`pps_id`,`name`,`banner`,`notes`) VALUES ';
        if ($action == 'insert') {
            foreach ($ports as $port) {
                $ins_sql .= "(" . $int->get_ID() . ", " . "(SELECT `id` FROM `sagacity`.`ports_proto_services` WHERE `port` = '" . $port->get_Port() . "'" . " AND `proto` = '" . (is_a($port, 'tcp_ports') ? 'tcp' : 'udp') . "' " . " AND `notes` NOT LIKE '%historic%' LIMIT 1), " . "'" . $this->conn->real_escape_string($port->get_IANA_Name()) . "', " . "'" . $this->conn->real_escape_string($port->get_Banner()) . "', " . "'" . $this->conn->real_escape_string($port->get_Notes()) . "'), ";
            }

            $ins_sql = substr($ins_sql, 0, - 1);

            if (strlen($ins_sql) > 84) {
                if (! $this->conn->real_query($ins_sql)) {
                    Sagacity_Error::sql_handler($ins_sql);
                    error_log($this->conn->error);
                    $ret = false;
                }
            }
        } else {}

        return $ret;
    }

    // }}}
    // {{{ TCP_PORTS CLASS FUNCTIONS
    /**
     * Get TCP port data
     *
     * @param integer $port_number
     *            [optional]
     *            Port number to retrieve from database
     *
     * @return array:tcp_ports|NULL Returns array of tcp ports, or null if none found
     */
    public function get_TCP_Ports($port_number = null)
    {
        $ret = [];
        $where = [
            [
                'field' => 'proto',
                'op' => '=',
                'value' => 'tcp'
            ]
        ];

        if (! is_null($port_number)) {
            $where[] = [
                'field' => 'port',
                'op' => '=',
                'value' => $port_number,
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("ports_proto_services", [
            'id',
            'port',
            'iana_Name',
            'banner',
            'notes'
        ], $where);

        $rows = $this->help->execute();
        if (isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = new tcp_ports($row['id'], $row['port'], $row['iana_Name'], $row['banner'], $row['notes']);
            }

            return $ret;
        }
        return null;
    }

    // }}}
    // {{{ UDP_PORTS CLASS FUNCTIONS
    /**
     * Get UDP port data
     *
     * @param integer $port_number
     *            Port number to retrieve from database
     *
     * @return array:udp_ports|NULL Returns array of udp ports, or null if none found
     */
    public function get_UDP_Ports($port_number = null)
    {
        $ret = [];
        $where = [
            [
                'field' => 'proto',
                'op' => '=',
                'value' => 'udp'
            ]
        ];

        if (! is_null($port_number)) {
            $where[] = [
                'field' => 'port',
                'op' => '=',
                'value' => $port_number,
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("ports_proto_services", [
            'id',
            'port',
            'iana_Name',
            'banner',
            'notes'
        ], $where);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = new udp_ports($row['id'], $row['port'], $row['iana_Name'], $row['banner'], $row['notes']);
            }

            return $ret;
        }
        return null;
    }

    // }}}
    // {{{ NESSUS CLASS FUNCTIONS
    /**
     * Function to retrieve a nessus object
     *
     * @param string $nessus_id
     *            Nessus ID of the object you want
     *
     * @return nessus|NULL Returns nessus object and associated references, or null if none found
     */
    public function get_Nessus($nessus_id)
    {
        $this->help->select("nessus_plugins np", null, [
            [
                'field' => 'np.plugin_id',
                'op' => '=',
                'value' => $nessus_id
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN sagacity.nessus n ON n.nessus_id = np.plugin_id"
            ]
        ]);

        $row = $this->help->execute();

        if (is_array($row) && count($row) && isset($row['plugin_id'])) {
            $nessus = new nessus($row['pdi_id'], $row['plugin_id']);

            $nessus->set_Name($row['name']);
            $nessus->set_Copyright($row['copyright']);
            $nessus->set_Version($row['version']);
            $nessus->set_FileDate($row['file_date']);
            $nessus->set_FileName($row['file_name']);

            $this->help->select("sagacity.nessus_meta", null, [
                [
                    'field' => 'plugin_id',
                    'op' => '=',
                    'value' => $row['plugin_id']
                ]
            ]);

            if ($rows = $this->help->execute()) {
                if (is_array($rows) && count($rows)) {
                    foreach ($rows as $row) {
                        $nessus->add_Reference($row['type'], $row['val']);
                    }
                }
            }

            return $nessus;
        }

        return null;
    }

    /**
     * Update Nessus data
     *
     * @param array:nessus|nessus $nessus
     *            Nessus object to update
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Nessus($nessus)
    {
        $nessus_arr = [];
        $meta_arr = [];
        $plugins_arr = [];
        $update_arr = [];

        $nessus_fields = array(
            'pdi_id',
            'nessus_id'
        );
        $meta_fields = array(
            'plugin_id',
            'type',
            'val'
        );
        $plugins_fields = array(
            'plugin_id',
            'name',
            'copyright',
            'version',
            'file_name',
            'file_date'
        );

        $this->help->create_table("tmp_nessus", true, array(
            array(
                'field' => 'plugin_id',
                'datatype' => 'int(11)',
                'options' => 'primary key'
            ),
            array(
                'field' => 'name',
                'datatype' => 'varchar(255)'
            ),
            array(
                'field' => 'copyright',
                'datatype' => 'varchar(255)'
            ),
            array(
                'field' => 'version',
                'datatype' => 'varchar(45)'
            ),
            array(
                'field' => 'file_name',
                'datatype' => 'varchar(100)'
            ),
            array(
                'field' => 'file_date',
                'datatype' => 'int(11)'
            )
        ));
        $this->help->execute();

        if (is_a($nessus, 'nessus')) {
            $nessus = array(
                0 => $nessus
            );
        }

        if (is_array($nessus)) {
            $refs = [];
            foreach ($nessus as $plug) {
                $db_nessus = $this->get_Nessus($plug->get_Nessus_ID());

                if (is_null($db_nessus)) {
                    if (! $plug->get_PDI_ID()) {
                        $pdi = new pdi(null, $plug->get_Category(), $plug->get_FileDate_Date());
                        $pdi->set_Short_Title($plug->get_Name());
                        $pdi->set_Group_Title($plug->get_Name());
                        $pdi->set_Description($plug->get_Description());
                        $pdi->set_ID($this->save_PDI($pdi));
                        $plug->set_PDI_ID($pdi->get_ID());

                        $stig = new stig($plug->get_PDI_ID(), $plug->get_Nessus_ID(), $plug->get_Name());
                        $this->add_Stig($stig);
                    }

                    $plugins_arr[] = [
                        $plug->get_Nessus_ID(),
                        $plug->get_Name(),
                        $plug->get_Copyright(),
                        $plug->get_Version(),
                        $plug->get_FileName(),
                        $plug->get_FileDate()
                    ];

                    $refs = $plug->get_Reference();
                } else {
                    $update_arr[] = [
                        $plug->get_Nessus_ID(),
                        $plug->get_Name(),
                        $plug->get_Copyright(),
                        $plug->get_Version(),
                        $plug->get_FileName(),
                        $plug->get_FileDate()
                    ];

                    $refs = $plug->compare_References($db_nessus);
                }

                $nessus_arr[] = [
                    $plug->get_PDI_ID(),
                    $plug->get_Nessus_ID()
                ];

                if (is_array($refs) && count($refs)) {
                    foreach ($refs as $type => $ref) {
                        foreach ($ref as $val) {
                            $meta_arr[] = array(
                                $plug->get_Nessus_ID(),
                                $type,
                                $val
                            );
                        }
                    }
                }
            }

            if (is_array($plugins_arr) && count($plugins_arr)) {
                $this->help->extended_insert("nessus_plugins", $plugins_fields, $plugins_arr, true);
                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                }
            }

            if (is_array($update_arr) && count($update_arr)) {
                $this->help->extended_insert("tmp_nessus", $plugins_fields, $update_arr, true);
                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                }

                $this->help->extended_update("nessus_plugins", "tmp_nessus", "plugin_id", $plugins_fields);
                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                }
            }

            if (is_array($nessus_arr) && count($nessus_arr)) {
                $this->help->extended_insert("nessus", $nessus_fields, $nessus_arr, true);
                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                }
            }

            if (is_array($meta_arr) && count($meta_arr)) {
                $this->help->extended_insert("nessus_meta", $meta_fields, $meta_arr, true);
                if (! $this->help->execute()) {
                    $this->help->debug(E_ERROR);
                }
            }
        } else {
            return false;
        }

        return true;
    }

    // }}}
    // {{{ OVAL CLASS FUNCTIONS
    /**
     * Getter function for oval
     *
     * @param string $oval_id
     *            Oval ID to retrieve from database
     *
     * @return oval|NULL Returns oval object, or null if none found
     */
    public function get_Oval($oval_id)
    {
        $oval = null;
        $sql = "SELECT " . "`pdi_id`, `oval_id`, `title`, `desc`, `platform`, `ext_def`, `ext_def_op` " . "FROM sagacity.oval " . "WHERE `oval_id` = '" . $this->conn->real_escape_string($oval_id) . "'";

        if ($res = $this->conn->query($sql)) {
            $row = $res->fetch_assoc();

            $oval = new oval($row['pdi_id'], $row['oval_id'], $row['title'], $row['desc'], $row['platform'], $row['ext_def'], $row['ext_def_op']);

            $sql = "SELECT" . "`oval_id`, `source`, `url`, `ref_id` " . "FROM sagacity.oval_ref " . "WHERE `oval_id` = '" . $this->conn->real_escape_string($row['oval_id']) . "'";

            if ($res2 = $this->conn->query($sql)) {
                while ($row2 = $res2->fetch_assoc()) {
                    $ref = new oval_ref($row2['oval_id'], $row2['source'], $row2['url'], $row2['ref_id']);

                    $oval->add_Reference($ref);
                }
            } else {
                Sagacity_Error::sql_handler($sql);
                error_log($this->conn->error);
            }

            return $oval;
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return null;
    }

    /**
     * Function to create a OVAL xml file to import into SCC
     *
     * @param string $os
     *            Operating system version to query
     *
     * @return string Returns string representing XML
     */
    public function get_OS_Oval($os)
    {
        $xmlns = "xmlns = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows'";
        // ------------------------------ Start <registry_test> -----------------------------
        // create temporary db table to combine all OVAL checks marked 'M' and not 'M'
        $tmp_sql = "CREATE TEMPORARY TABLE `tmp_oval` SELECT " . "pdi.`id`, o.`oval_id`, s.`stig_id`, vms.`vms_id`, pdi.`check_contents`, pdi.`short_title` " . "FROM `pdi_catalog` AS pdi " . "LEFT JOIN `oval` AS o ON pdi.`id` = o.`pdi_id` " . "LEFT JOIN `stigs` AS s ON pdi.`id` = s.`pdi_id` " . "LEFT JOIN `golddisk` AS vms ON pdi.`id` = vms.`pdi_id` " . "LEFT JOIN `pdi_checklist_lookup` AS lookup ON pdi.`id` = lookup.`pdi_id` " . "LEFT JOIN `checklist` AS c ON lookup.`checklist_id` = c.`id` " . "LEFT JOIN `software` AS sft ON sft.`id` = c.`sw_id` " . "WHERE " . "o.`oval_id` = 'M' AND " . "pdi.`check_contents` LIKE '%Registry Hive%' AND " . "sft.`man` = 'MS' AND " . "sft.`name` = 'Windows' AND " . "sft.`ver` = '$os' " . "GROUP BY `stig_id`";

        $this->conn->real_query($tmp_sql);

        // delete rows in temporary table from other checklist that cannot designated as manual
        $del_sql = "DELETE FROM tmp_oval " . "WHERE `id` IN (" . "SELECT pdi.`id` " . "FROM `pdi_catalog` AS pdi " . "LEFT JOIN `oval` AS o ON pdi.`id` = o.`pdi_id` " . "LEFT JOIN `stigs` AS s ON pdi.`id` = s.`pdi_id` " . "LEFT JOIN `golddisk` AS vms ON pdi.`id` = vms.`pdi_id` " . "LEFT JOIN `pdi_checklist_lookup` AS lookup ON pdi.`id` = lookup.`pdi_id` " . "LEFT JOIN `checklist` AS c ON lookup.`checklist_id` = c.`id` " . "LEFT JOIN `software` AS sft ON sft.`id` = c.`sw_id` " . "WHERE " . "o.`oval_id` != 'M' AND " . "pdi.`check_contents` REGEXP 'Registry Hive' AND " . "sft.`man` = 'MS' AND " . "sft.`name` = 'Windows' AND " . "sft.`ver` = '$os' " . "GROUP BY pdi.`id`)";

        $this->conn->real_query($del_sql);

        $sql = "SELECT " . "`id`, `oval_id`, `stig_id`, `vms_id`, `check_contents`, `short_title` " . "FROM `tmp_oval`";

        if ($sth = $this->conn->prepare($sql)) {
            if ($sth->execute()) {
                $pdi_id = 0;
                $oval_id = '';
                $stig_id = '';
                $vms_id = '';
                $check_contents = '';
                $short_title = '';
                $x = 0;
                $sth->bind_result($pdi_id, $oval_id, $stig_id, $vms_id, $check_contents, $short_title);
                // oval_file xml validation check
                $root = '<?xml version="1.0" encoding="UTF-8"?><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:windows-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#windows" xmlns:independent-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5#windows http://oval.mitre.org/language/download/schema/version5.3/ovaldefinition/complete/windows-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent http://oval.mitre.org/language/download/schema/version5.3/ovaldefinition/complete/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 http://oval.mitre.org/language/download/schema/version5.3/ovaldefinition/complete/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 http://oval.mitre.org/language/download/schema/version5.3/ovaldefinition/complete/oval-common-schema.xsd">';
                // declaring string variables and setting values to empty
                $def = '';
                $tst = '';
                $obj = '';
                $ste = '';
                // generator node in xml format
                $date = new DateTime(); // insert date and time when file completed
                $gen = "<generator><oval:product_name>DISA FSO</oval:product_name><oval:schema_version>5.3</oval:schema_version><oval:timestamp>" . $date->format(DATE_W3C) . "</oval:timestamp></generator>";

                while ($sth->fetch()) {
                    $x ++;
                    $match = [];
                    preg_match('/Registry Hive: +(\S*)/', $check_contents, $match);
                    $hive = $match[1];

                    preg_match('/(Subkey|Path|Registry Path): +(\\\)?(.*)/', $check_contents, $match);
                    $path = is_array($match) && count($match) > 3 ? $match[3] : "STIG ID: $stig_id" . PHP_EOL;

                    preg_match('/Value Name: +(\S*)/', $check_contents, $match);
                    $name = is_array($match) && count($match) > 1 ? $match[1] : '';

                    if (is_array($match) && count($match) == 2) {
                        $c_operator = 'AND';
                        $c_count = 1;
                    }

                    preg_match('/Type: +(\S*)/', $check_contents, $match);
                    $type = is_array($match) && count($match) > 0 ? $match[1] : "PDI ID: $pdi_id" . PHP_EOL;

                    preg_match('/Value: +(\S*)/', $check_contents, $match);
                    $value = is_array($match) && count($match) > 0 ? $match[1] : "PDI ID: $pdi_id" . PHP_EOL;

                    if (strpos($type, "PDI ID: " . $pdi_id) !== false) {
                        // print "$pdi_id, $vms_id this VMS item cannot be automated".PHP_EOL.PHP_EOL;
                        continue;
                    }

                    // variables set for various xml nodes
                    $def_id = 'oval:smc.gpea.windows:def:' . $pdi_id;
                    $tst_id = 'oval:smc.gpea.windows:tst:' . $pdi_id . "00";
                    $ste_id = 'oval:smc.gpea.windows:ste:' . $pdi_id . "00";
                    $obj_id = 'oval:smc.gpea.windows:obj:' . $pdi_id . "00";
                    $var_id = 'oval:smc.gpea.windows:var:' . $pdi_id . "00";
                    $def_class = 'compliance';
                    $m_family = 'windows';
                    $aft_platform = 'Microsoft Windows ' . $os;
                    $tst_chk_existence = ($c_count == 1 ? "all_exist" : '');

                    // definitions node in xml format
                    $def .= "<definition id='$def_id' version='1' class='$def_class'>" . "<metadata>" . "<title>$short_title</title>" . "<affected family='$m_family'>" . "<platform>$aft_platform</platform>" . "</affected>" . "<reference source='' ref_url='' ref_id='' />" . "<description>$short_title</description>" . "</metadata>" . "<criteria operator='$c_operator'>";

                    if ($c_count == 1) {
                        $def .= "<criterion test_ref='oval:smc.gpea.windows:tst:" . $pdi_id . "00' comment='" . $hive . "\\" . $path . "!" . $name . " value equals variable' />" . PHP_EOL;
                    }

                    $def .= "</criteria></definition>";

                    $tst .= "<registry_test $xmlns id='$tst_id' version='1' check_existence='$tst_chk_existence' check='all' comment='comment'>" . "<object object_ref='$obj_id' />" . "<state state_ref='$ste_id' />" . "</registry_test>";

                    if (substr($path, - 1) != "\\") {
                        $path .= "\\";
                    }

                    $obj .= "<registry_object $xmlns id='$obj_id' version='1' comment='comment'>" . "<hive datatype='string'>" . strtoupper($hive) . "</hive>" . "<key datatype='string'>$path</key>" . "<name datatype='string'>$name</name>" . "</registry_object>";

                    $ste .= "<registry_state $xmlns id='$ste_id' version='1' comment='comment'>" . "<type>" . strtolower($type) . "</type>" . "<value datatype='" . (strpos(strtolower($type), 'sz') ? 'string' : 'int') . "' operation='equals'>$value</value>" . "</registry_state>";
                }
                $sth->close();
            }
        }
        // ------------------------------ End <registry_test> -----------------------------
        // ------------------------------ Start <auditeventpolicysubcategories_test> -----------------------------
        $tmp_sql = "CREATE TEMPORARY TABLE `tmp_oval` SELECT " . "pdi.`id`,o.`oval_id`,s.`stig_id`,vms.`vms_id`,pdi.`check_contents`,pdi.`short_title` " . "FROM `sagacity`.`pdi_catalog` AS pdi " . "LEFT JOIN `sagacity`.`oval` AS o ON pdi.`id`=o.`pdi_id` " . "LEFT JOIN `sagacity`.`stigs` AS s ON pdi.`id`=s.`pdi_id` " . "LEFT JOIN `sagacity`.`golddisk` AS vms ON pdi.`id`=vms.`pdi_id` " . "LEFT JOIN `sagacity`.`pdi_checklist_lookup` AS lookup ON pdi.`id`=lookup.`pdi_id` " . "LEFT JOIN `sagacity`.`checklist` AS c ON lookup.`checklist_id`=c.`id` " . "LEFT JOIN `sagacity`.`software` AS sft ON sft.`id`=c.`sw_id` " . "WHERE " . "o.`oval_id`='M' AND " . "pdi.`check_contents` LIKE '%AuditPol%' AND " . "sft.`man`='MS' AND " . "sft.`name`='Windows' AND " . "sft.`ver`='$os' " . "GROUP BY `stig_id`";
        $this->conn->real_query($tmp_sql);

        $del_sql = "DELETE FROM tmp_oval " . "WHERE `id` IN (" . "SELECT pdi.`id` " . "FROM `sagacity`.`pdi_catalog` AS pdi " . "LEFT JOIN `sagacity`.`oval` AS o ON pdi.`id`=o.`pdi_id` " . "LEFT JOIN `sagacity`.`stigs` AS s ON pdi.`id`=s.`pdi_id` " . "LEFT JOIN `sagacity`.`golddisk` AS vms ON pdi.`id`=vms.`pdi_id` " . "LEFT JOIN `sagacity`.`pdi_checklist_lookup` AS lookup ON pdi.`id`=lookup.`pdi_id` " . "LEFT JOIN `sagacity`.`checklist` AS c ON lookup.`checklist_id`=c.`id` " . "LEFT JOIN `sagacity`.`software` AS sft ON sft.`id`=c.`sw_id` " . "WHERE " . "o.`oval_id`!='M' AND " . "pdi.`check_contents` REGEXP 'AuditPol' AND " . "sft.`man`='MS' AND " . "sft.`name`='Windows' AND " . "sft.`ver`='$os' " . "GROUP BY pdi.`id`)";
        $this->conn->real_query($del_sql);

        $sql = "SELECT " . "`id`,`oval_id`,`stig_id`,`vms_id`,`check_contents`,`short_title` " . "FROM `tmp_oval`";

        if ($sth = $this->conn->prepare($sql)) {
            if ($sth->execute()) {
                $pdi_id = 0;
                $oval_id = '';
                $stig_id = '';
                $vms_id = '';
                $check_contents = '';
                $short_title = '';
                $x = 0;
                $sth->bind_result($pdi_id, $oval_id, $stig_id, $vms_id, $check_contents, $short_title);

                $sth->store_result();

                if ($sth->num_rows > 0) {
                    $obj .= "<auditeventpolicysubcategories_object $xmlns id='oval:smc.gpea.windows:obj:1' version='1' comment='Audit Event Policy Subcategories' />";
                }

                while ($sth->fetch()) {
                    $tst_id = "oval:smc.gpea.windows:tst:" . $pdi_id . "00";
                    $ste_id = "oval:smc.gpea.windows:ste:" . $pdi_id . "00";

                    $arrow_idx = strpos($check_contents, '->') + 3;
                    $dash_idx = strpos($check_contents, ' - ');

                    $subcat = substr($check_contents, $arrow_idx, $dash_idx - $arrow_idx);
                    $tag = str_replace(' ', '_', strtolower($subcat));

                    $audit = substr($check_contents, $dash_idx + 3);

                    $ste .= "<auditeventpolicysubcategories_state $xmlns id='$ste_id' version='1' comment='comment'>" . "<$tag datatype='string'>" . ($audit == 'Failure' ? 'AUDIT_FAILURE' : 'AUDIT_SUCCESS') . "</$tag>" . "</auditeventpolicysubcategories_state>";

                    $tst .= "<auditeventpolicysubcategories_test $xmlns id='$tst_id' version='1' check_existence='at_least_one_exists' check='all' comment='comment'>" . "<object object_ref='oval:smc.gpea.windows:obj:1' />" . "<state state_ref='$ste_id' />" . "</auditeventpolicysubcategories_test>";
                }
            } else {
                error_log($sth->error);
            }
        } else {
            error_log($this->conn->error);
        }

        // ------------------------------ End <auditeventpolicysubcategories_test> -----------------------------
        // ------------------------------ Start <passwordpolicy_test> -----------------------------
        // ------------------------------ End <passwordpolicy_test> -----------------------------

        $xml_string = $root . "$gen<definitions>$def</definitions><tests>$tst</tests><objects>$obj</objects><states>$ste</states></oval_definitions>";

        return $xml_string;
    }

    /**
     * Function to get oval constant data from database
     *
     * @param string $oval_id
     *            Oval ID to get constant data for
     *
     * @return array Returns array of constant ID and value
     */
    public function get_Oval_Const($oval_id)
    {
        $sql = "SELECT `const_id`,`value` FROM `sagacity`.`ov_convert` WHERE `var_id`=" . $oval_id;

        if ($res = $this->conn->query($sql)) {
            $vals = [];
            while ($row = $res->fetch_assoc()) {
                $vals[] = $row['value'];
            }

            return array(
                'const_id' => $row['const_id'],
                'values' => $vals
            );
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
            return null;
        }
    }

    /**
     * Function to add an Oval
     *
     * @param oval $oval
     *            Oval to add to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function add_Oval($oval)
    {
        $this->help->insert("sagacity.oval", array(
            'pdi_id' => $oval->get_PDI_ID(),
            'oval_id' => $oval->get_Oval_ID(),
            'title' => $oval->get_Title(),
            'desc' => $oval->get_Description(),
            'platform' => $oval->get_Platform(),
            'ext_def' => $oval->get_External_Definition(),
            'ext_def_op' => $oval->get_External_Definition_Operator()
        ), true);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to save oval data
     *
     * @param oval $oval_in
     *            Oval to update database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Oval($oval_in)
    {
        $this->help->replace("sagacity.oval", array(
            'pdi_id' => $oval_in->get_PDI_ID(),
            'oval_id' => $oval_in->get_Oval_ID(),
            'title' => $oval_in->get_Title(),
            'desc' => $oval_in->get_Description(),
            'platform' => $oval_in->get_Platform(),
            'ext_def' => $oval_in->get_External_Definition(),
            'ext_def_op' => $oval_in->get_External_Definition_Operator()
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ PDI_CATALOG CLASS FUNCTIONS
    /**
     * Function to retrieve a PDI from the database
     *
     * @param integer $pdi_id
     *            PDI ID to get from database
     * @param integer $chk_id
     *            Checklist ID to filter on
     *
     * @return pdi|NULL Returns PDI object, or null if none found
     */
    public function get_PDI($pdi_id, $chk_id = null)
    {
        $pdi = null;
        $this->help->select("sagacity.pdi_catalog p", null, [
            [
                'field' => 'p.id',
                'op' => '=',
                'value' => $pdi_id
            ]
        ]);

        $row = $this->help->execute();

        if (is_array($row) && count($row) && isset($row['id'])) {
            $pdi = new pdi($row['id'], $row['cat'], $row['update']);
            $pdi->set_Short_Title($row['short_title']);
            $pdi->set_Check_Contents($row['check_contents']);

            if (! is_null($chk_id)) {
                $this->help->select("sagacity.pdi_checklist_lookup", null, [
                    [
                        'field' => 'pdi_id',
                        'op' => '=',
                        'value' => $pdi_id
                    ],
                    [
                        'field' => 'checklist_id',
                        'op' => '=',
                        'value' => $chk_id,
                        'sql_op' => 'AND'
                    ]
                ]);

                $row = $this->help->execute();
                if (is_array($row) && count($row) && isset($row['pdi_id'])) {
                    $pdi->set_Short_Title($row['short_title']);
                    $pdi->set_Group_Title($row['group_title']);
                    $pdi->set_Check_Contents($row['check_contents']);
                    $pdi->set_Fix_Text($row['fix_text']);
                }
            }
        }

        return $pdi;
    }

    /**
     * Function to get pdi catalog item from database
     *
     * @param integer $pdi_id
     *            Get PDI Catalog entry from database using this ID
     *
     * @return array|NULL Returns associative array with record, or null if none found
     */
    public function get_PDI_Catalog($pdi_id)
    {
        $this->help->select("sagacity.pdi", null, array(
            array(
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $pdi_id
            )
        ));

        return $this->help->execute();
    }

    /**
     * Function to attempt to match text
     *
     * @param pdi $pdi
     *            PDI to match in database
     * @param nessus $nessus
     *            Nessus to match in database
     * @param cve $cve
     *            CVE to match in database
     * @param iavm $iavm
     *            IAVM to match in database
     *
     * @return array|NULL Returns array of possible matches, or null if none found
     */
    public function get_Matching_PDIs($pdi, $nessus, $cve, $iavm)
    {
        /*
         * $string = '';
         *
         * if (!is_null($nessus)) {
         * $string = $nessus->get_Name() . ' ' . $nessus->get_Description() . ' ' . $nessus->get_Summary();
         * }
         * elseif (!is_null($cve)) {
         * $string = $cve->get_Description();
         * }
         * elseif (!is_null($iavm)) {
         * $string = $iavm->get_Title() . ' ' . $iavm->get_Executive_Summary();
         * }
         *
         * foreach ($this->DISALLOWED as $word) {
         * $string = preg_replace("/\s" . $word . "\s/i", " ", $string);
         * }
         *
         * $sql = "SELECT " .
         * "MATCH(pdi.`short_title`,pdi.`description`,pdi.`check_content`) " .
         * "AGAINST('" . $this->conn->real_escape_string($string) . "' IN NATURAL LANGUAGE MODE) AS 'score'," .
         * "pdi.`id`,pdi.`short_title`,pdi.`description`,pdi.`check_content` " .
         * "FROM `sagacity`.`pdi_catalog` pdi " .
         * "GROUP BY pdi.`id`,`score` " .
         * "HAVING `score` > 10 " .
         * "ORDER BY `score` DESC " .
         * "LIMIT 0, 5";
         *
         * $ret = [];
         *
         * if ($res = $this->conn->query($sql)) {
         * while ($row = $res->fetch_assoc()) {
         * $ret[] = array(
         * 'score' => number_format($row['score'], 3),
         * 'pdi_id' => $row['id'],
         * 'title' => $row['short_title'],
         * 'check_content' => $row['check_content'],
         * 'desc' => $row['description']
         * );
         * }
         *
         * return $ret;
         * }
         * else {
         * Sagacity_Error::sql_handler($sql);
         * error_log($this->conn->error);
         * }
         */
        return null;
    }

    /**
     * Function to try and find a PDI
     *
     * @param array $data_in
     *            An array of a type and value to search for. This will primarily be intended for types that don't have a readily available link to a PDI (nessus, retina, CVE, IAVM, etc).
     *
     * @return integer Returns the PDI id of the matching entry, or 0 if none found
     */
    public function find_PDI($data_in)
    {
        if ($data_in['type'] == 'nessus') {
            $nessus = $this->get_Nessus($data_in['value']);

            if (is_null($nessus)) {
                return 0;
            }

            if ($nessus->get_PDI_ID()) {
                return $nessus->get_PDI_ID();
            } else {
                $cves = $nessus->get_Reference_By_Type('cve');
                foreach ($cves as $cve_num) {
                    $cve = $this->get_CVE($cve_num);
                    if ($cve->get_PDI_ID()) {
                        return $cve->get_PDI_ID();
                    }

                    $sql = "SELECT `noticeId` FROM `sagacity`.`iavm_to_cve` WHERE `cve_id`='" . $this->conn->real_escape_string($cve_num) . "'";
                    if ($res = $this->conn->query($sql)) {
                        while ($row = $res->fetch_assoc()) {
                            $iavm = $this->get_IAVM($row['noticeId']);

                            if (! is_null($iavm)) {
                                return $iavm->get_PDI_ID();
                            }
                        }
                    } else {
                        Sagacity_Error::sql_handler($sql);
                        error_log($this->conn->error);
                    }
                }

                $bids = $nessus->get_Reference_By_Type('bid');
                foreach ($bids as $bid_num) {
                    $sql = "SELECT iavm.`pdi_id` " . "FROM `sagacity`.`nessus_refs` nr " . "JOIN `sagacity`.`iavm_bids` ib ON ib.`bid`=nr.`val` " . "JOIN `sagacity`.`iavm_notices` iavm ON iavm.`noticeId`=ib.`iavm_notice_id` " . "WHERE " . "nr.`type`='bid' AND " . "nr.`val`=" . $this->conn->real_escape_string($bid_num) . " AND " . "nr.`plugin_id`=" . $this->conn->real_escape_string($nessus->get_Nessus_ID());
                    if ($res = $this->conn->query($sql)) {
                        while ($row = $res->fetch_assoc()) {
                            return $row['pdi_id'];
                        }
                    }
                }
            }
        }
        return 0;
    }

    /**
     * Function to save an existing PDI
     *
     * @param pdi $pdi_in
     *            The PDI to save or update
     * @param checklist $checklist
     *            [optional]
     *            The checklist to link new PDIs to (if null links to Orphan checklist)
     *
     * @return boolean|int Returns ID of PDI or FALSE if failed to save.
     */
    public function save_PDI($pdi_in, $checklist = null)
    {
        $pdi_id = null;

        if ($pdi_in->get_ID()) {
            $this->help->update('sagacity.pdi_catalog', [
                'cat' => $pdi_in->get_Category_Level(),
                'update' => $pdi_in->get_Last_Update(),
                'short_title' => $pdi_in->get_Short_Title(),
                'check_contents' => $pdi_in->get_Check_Contents()
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $pdi_in->get_ID()
                ]
            ]);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }

            $pdi_id = $pdi_in->get_ID();
        } else {
            $this->help->insert("sagacity.pdi_catalog", [
                "cat" => $pdi_in->get_Category_Level(),
                'update' => $pdi_in->get_Last_Update(),
                'short_title' => $pdi_in->get_Short_Title(),
                'check_contents' => $pdi_in->get_Check_Contents()
            ]);

            if (! ($pdi_id = $this->help->execute())) {
                $this->help->debug(E_ERROR);
                return false;
            }

            $pdi_in->set_ID($pdi_id);
        }

        if (is_null($checklist)) {
            $checklist = $this->get_Checklist('Orphan');
        }

        if (is_array($checklist) && isset($checklist[0]) && is_a($checklist[0], 'checklist')) {
            $this->help->insert('sagacity.pdi_checklist_lookup', [
                'pdi_id' => $pdi_id,
                'checklist_id' => $checklist[0]->get_ID(),
                'check_contents' => $pdi_in->get_Check_Contents(),
                'group_title' => $pdi_in->get_Group_Title(),
                'short_title' => $pdi_in->get_Short_Title(),
                'fix_text' => $pdi_in->get_Fix_Text()
            ], true);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }
        } elseif (is_a($checklist, 'checklist')) {
            $this->help->insert("sagacity.pdi_checklist_lookup", array(
                'pdi_id' => $pdi_id,
                'checklist_id' => $checklist->get_ID(),
                'check_contents' => $pdi_in->get_Check_Contents(),
                'group_title' => $pdi_in->get_Group_Title(),
                'short_title' => $pdi_in->get_Short_Title(),
                'fix_text' => $pdi_in->get_Fix_Text()
            ), true);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }
        } else {
            Sagacity_Error::err_handler("Cannon link PDI ID $pdi_id with a checklist", E_WARNING);
        }

        return $pdi_id;
    }

    /**
     * Function to save the check contents to a specific PDI and checklist
     *
     * @param pdi $pdi_in
     *            The PDI (containing the check contents)
     * @param checklist $checklist_in
     *            The checklist
     * @param string $check_contents_in
     *            [optional]
     *            The check contents to save (will use check contents in $pdi_in if this is null)
     * @param string $fix_text_in
     *            [optional]
     *            The fix text to save
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Check_Contents($pdi_in, $checklist_in, $check_contents_in = null, $fix_text_in = null)
    {
        $this->help->replace("sagacity.pdi_checklist_lookup", array(
            'pdi_id' => $pdi_in->get_ID(),
            'checklist_id' => $checklist_in->get_ID(),
            'group_title' => $pdi_in->get_Group_Title(),
            'short_title' => $pdi_in->get_Short_Title(),
            'check_contents' => (! is_null($check_contents_in) ? $check_contents_in : $pdi_in->get_Check_Contents()),
            'fix_text' => (! is_null($fix_text_in) ? $fix_text_in : $pdi_in->get_Fix_Text())
        ));

        if (! $this->help->execute()) {
            return false;
        }
        return true;
    }

    // }}}
    // {{{ PROC_IA_CONTROLS CLASS FUNCTIONS
    /**
     * Function to get all procedural IA controls for specified system
     *
     * @param ste $ste_in
     *            ST&E to query the database for
     * @param string $control_id
     *            [optional]
     *            Control ID to query (default null)
     *
     * @return array:proc_ia_controls Return array of proc_ia_controls and associated sub controls, or empty array if none found
     */
    public function get_Proc_IA_Controls($ste_in, $control_id = null)
    {
        $ret = [];
        $sys = $this->get_System($ste_in->get_System()
            ->get_ID())[0];
        switch ($sys->get_Classification()) {
            case 'Public':
                $class = 'pub';
                break;
            case 'Sensitive':
                $class = 'sen';
                break;
            case 'Classified':
                $class = 'cl';
                break;
            default:
                $class = '';
        }

        $sql = "SELECT " . "pia.`control_id`,pia.`name`,pia.`subject_area`,pia.`description`," . "pia.`threat_vul_cm`,pia.`gen_imp_guide`,pia.`guide_resource`,pia.`impact` " . "FROM `sagacity`.`proc_ia_controls` pia " . "LEFT JOIN `sagacity`.`proc_level_type` plt ON plt.`proc_control`=pia.`control_id` " . "WHERE plt.`type`='diacap' AND " . "plt.`level`=" . $sys->get_MAC() . " AND " . "plt.`class`='$class'";

        if (! is_null($control_id)) {
            $sql .= " AND pia.`control_id`='" . $this->conn->real_escape_string($control_id) . "'";
        }

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $ia = new proc_ia_controls($row['control_id'], $row['name'], $row['subject_area'], $row['description'], $row['threat_vul_cm'], $row['gen_imp_guide'], $row['guide_resource'], $row['impact']);

                $sql2 = "SELECT `ste_id`,`control_id`,`vul_desc`,`mitigations`,`references`,`risk_analysis`,`notes`,`done` " . "FROM `sagacity`.`control_findings` " . "WHERE `ste_id`=" . $ste_in->get_ID() . " AND " . "`control_id`='" . $row['control_id'] . "'";
                if ($res2 = $this->conn->query($sql2)) {
                    if ($res2->num_rows > 0) {
                        $row2 = $res2->fetch_assoc();

                        $ia->finding->control_id = $row2['control_id'];
                        $ia->finding->ste_id = $row2['ste_id'];
                        $ia->finding->vul_desc = $row2['vul_desc'];
                        $ia->finding->mitigations = $row2['mitigations'];
                        $ia->finding->reference = $row2['references'];
                        $ia->finding->notes = $row2['notes'];
                        $ia->finding->risk_analysis = $row2['risk_analysis'];
                        $ia->finding->done = $row2['done'];
                    }
                }

                $sql2 = "SELECT " . "`sub_control_id`,`name`,`objective`," . "`prep`,`script`,`exp_result` " . "FROM `sagacity`.`proc_ia_sub_controls` " . "WHERE `parent_control_id`='" . $row['control_id'] . "'";

                if ($res2 = $this->conn->query($sql2)) {
                    while ($row2 = $res2->fetch_assoc()) {
                        $ia_sub = new proc_sub_ia_controls($row2['sub_control_id'], $row2['name'], $row2['objective'], $row2['prep'], $row2['script'], $row2['exp_result']);

                        $sql3 = "SELECT " . "`ste_id`,`proc_id`,`status`,`test_results`," . "`mitigations`,`milestones`,`ref`,`notes` " . "FROM `sagacity`.`proc_findings` " . "WHERE `ste_id`=" . $ste_in->get_ID() . " AND " . "`proc_id`='" . $row2['sub_control_id'] . "'";

                        if ($res3 = $this->conn->query($sql3)) {
                            if ($res3->num_rows > 0) {
                                $row3 = $res3->fetch_assoc();

                                $ia_sub->finding->control_id = $row3['proc_id'];
                                $ia_sub->finding->ste_id = $row3['ste_id'];
                                $ia_sub->finding->test_result = $row3['test_results'];
                                $ia_sub->finding->mitigation = $row3['mitigations'];
                                $ia_sub->finding->milestone = $row3['milestones'];
                                $ia_sub->finding->reference = $row3['ref'];
                                $ia_sub->finding->notes = $row3['notes'];
                                $ia_sub->finding->status = $row3['status'];
                            } else {
                                $ia_sub->finding->status = 'Not Reviewed';
                            }
                        }

                        $ia->add_Sub($ia_sub);
                    }
                }

                $ret[] = $ia;
            }
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return $ret;
    }

    // }}}
    // {{{ INTERVIEW QUESTION CLASS FUNCTIONS
    /**
     * Function to return the categories
     *
     * @return array:string
     */
    public function get_Question_Categories()
    {
        $ret = [];
        $this->help->select("interview_questions", [
            'cat'
        ], [], [
            'group' => 'cat'
        ]);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = $row['cat'];
            }
        }

        return $ret;
    }

    /**
     * Function to get the questions
     *
     * @param integer $cat_in
     * @param string $type_in
     */
    public function get_Questions($cat_in, $type_in = null)
    {
        $ret = [];
        $sql = "SELECT " . "iq.`id`,iq.`key`,iq.`cat`,iq.`question`," . "(SELECT ci.`answer` " . "FROM `category_interview` ci " . "WHERE ci.`ques_id`=iq.`id` AND ci.`cat_id`=" . $this->conn->real_escape_string($cat_in) . ") AS 'answer' " . "FROM `interview_questions` iq " . "WHERE iq.`cat`='" . $this->conn->real_escape_string($type_in) . "'";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $ques = new question();
                $ques->id = $row['id'];
                $ques->cat = $row['cat'];
                $ques->key = $row['key'];
                $ques->question = $row['question'];
                $ques->answer = $row['answer'];

                $ret[] = $ques;
            }
        } else {
            print $sql . "<br />";
            print $this->conn->error;
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return $ret;
    }

    /**
     * Function to return the interview questions with their answers
     *
     * @param int $cat_id_in
     *
     * @return array:question
     */
    public function get_Interview_Answers($cat_id_in)
    {
        $ret = [];
        $this->help->select("interview_questions iq", [
            'iq.id',
            'iq.key',
            'iq.question',
            'ci.answer'
        ], [
            [
                'field' => 'ci.cat_id',
                'op' => '=',
                'value' => $cat_id_in
            ]
        ], [
            'table_joins' => "LEFT JOIN category_interview ci ON iq.id = ci.ques_id"
        ]);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ques = new question();

                $ques->id = $row['id'];
                $ques->key = $row['key'];
                $ques->question = $row['question'];
                $ques->answer = ($row['answer'] ? true : false);

                $ret[] = $ques;
            }
        }

        return $ret;
    }

    /**
     * Function to reset the interview answers
     *
     * @param string $type_in
     * @param int $cat_in
     */
    public function set_Questions($type_in, $cat_in)
    {
        $this->help->delete("category_interview", null, [
            [
                'field' => 'cat_id',
                'op' => '=',
                'value' => $cat_in
            ]
        ]);
        $this->help->execute();

        $this->help->sql = "INSERT IGNORE INTO `category_interview` (`cat_id`,`ques_id`)" . " SELECT " . $this->conn->real_escape_string($cat_in) . ",`id`" . " FROM `interview_questions`" . " WHERE `cat`='" . $this->conn->real_escape_string($type_in) . "'";
        $this->help->query_type = db_helper::INSERT;

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to set the answer for an interview question
     *
     * @param int $cat_id_in
     * @param question $question
     * @return boolean
     */
    public function set_QA($cat_id_in, $question)
    {
        $this->help->update("category_interview", [
            'answer' => ($question->answer)
        ], [
            [
                'field' => 'ques_id',
                'op' => '=',
                'value' => $question->id
            ],
            [
                'field' => 'cat_id',
                'op' => '=',
                'value' => $cat_id_in,
                'sql_op' => 'AND'
            ]
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ RETINA CLASS FUNCTIONS
    /**
     * Update retina data
     *
     * @param retina $retina_In
     *            Retina object to save to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Retina($retina_In)
    {
        $sql = "REPLACE INTO `sagacity`.`retina` (`pdi_id`,`retina_id`) VALUES (" . $this->conn->real_escape_string($retina_In->get_PDI_ID()) . "," . $this->conn->real_escape_string($retina_In->get_Retina_ID()) . ")";

        if (! $this->conn->real_query($sql)) {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ RMF_CONTROL CLASS FUNCTIONS
    /**
     * Function to get all the RMF controls that apply to a certain baseline impact<br />
     * Used for tailoring later
     *
     * @param string $baseline
     *
     * @return array:rmf_control
     */
    public function get_RMF_Control_By_Baseline($baseline)
    {
        $ret = [];
        if (! in_array($baseline, array(
            "low",
            "moderate",
            "high"
        ))) {
            return [];
        }

        $sql = "SELECT " . "f.`abbr`,f.`name` AS 'family_name' " . "c.`control_id`,c.`name` AS 'control_name',c.`pri`,c.`statement`,c.`guidance` " . "cb.`impact_level` " . "FROM `rmf`.`controls` c " . "JOIN `rmf`.`control_baseline` cb ON cb.`control_id`=c.`control_id` " . "JOIN `rmf`.`family` f ON f.`abbr`=c.`family_id` " . "WHERE cb.`impact_level`='" . $this->conn->real_escape_string($baseline) . "'";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $family = new rmf_family();
                $family->set_Abbr($row['abbr']);
                $family->set_Name($row['family_name']);

                $rmf = new rmf_control();
                $rmf->family = $family;
                $rmf->set_Control_ID($row['control_id']);
                $rmf->set_Name($row['control_name']);
                $rmf->set_Priority($row['pri']);
                $rmf->set_Statement($row['statement']);
                $rmf->set_Guidance($row['guidance']);
                $rmf->set_Baseline($baseline, true);

                $this->get_RMF_Related_Controls($rmf);
                $this->get_RMF_Enhanced_Controls($rmf, $baseline);

                $ret[] = $rmf;
            }
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return $ret;
    }

    /**
     * Function to get all the related controls
     *
     * @param rmf_control $rmf
     */
    public function get_RMF_Related_Controls(rmf_control &$rmf)
    {
        $sql = "SELECT rc.`related_control_id` " . "FROM `rmf`.`related_controls rc " . "WHERE rc.`control_id`='" . $this->conn->real_escape_string($rmf->get_Control_ID()) . "'";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $rmf->add_Related_Control($row['related_control_id']);
            }
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }
    }

    /**
     * Function to get all the enhanced controls
     *
     * @param rmf_control $rmf
     * @param string $baseline
     */
    public function get_RMF_Enhanced_Controls(rmf_control &$rmf, $baseline = null)
    {
        $sql = "SELECT " . "ce.`enh_id`,ce.`name`,ce.`desc`,ce.`guidance` " . "FROM `rmf`.`control_enh` ce " . "JOIN `rmf`.`enhancement_baseline eb ON eb.`control_id`=ce.`control_id` AND " . "eb.`enh_id`=ce.`enh_id` " . "WHERE ce.`control_id`='" . $this->conn->real_escape_string($rmf->get_Control_ID()) . "' AND " . "eb.`impact`='" . (is_null($baseline) ? $rmf->get_Worst_Baseline() : $baseline) . "'";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $enh = new rmf_control_enhancements();
                $enh->set_Enhanced_ID($row['enh_id']);
                $enh->set_Guidance($row['guidance']);
                $enh->set_Name($row['name']);
                $enh->set_Statement($row['desc']);

                $rmf->add_Enhanced_Control($enh);
            }
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }
    }

    // }}}
    // {{{ SCAN CLASS FUNCTIONS
    /**
     * Get ScanData for Results page
     *
     * @param integer $intSTE
     *            ST&E ID to grab scans for
     * @param integer|string $Scan_ID
     *            [optional]
     *            Scan ID or file name to grab (defaulted null)
     *
     * @return array:scan|NULL Returns array of scans associated with the ST&E, or null if none found
     */
    public function get_ScanData($intSTE, $Scan_ID = null, $status_in = null, $type_in = null)
    {
        $ret = [];
        $where = [
            [
                'field' => 's.ste_id',
                'value' => $intSTE
            ]
        ];

        if (! is_null($Scan_ID)) {
            if (is_numeric($Scan_ID)) {
                $where[] = [
                    'field' => 's.id',
                    'value' => $Scan_ID,
                    'sql_op' => 'AND'
                ];
            } else {
                $where[] = [
                    'field' => 's.file_name',
                    'value' => $Scan_ID,
                    'sql_op' => 'AND'
                ];
            }
        }

        if (! is_null($status_in)) {
            $where[] = [
                'field' => 's.status',
                'value' => $status_in,
                'sql_op' => 'AND'
            ];
        }

        if (! is_null($type_in)) {
            $where[] = [
                'field' => 'src.name',
                'value' => $type_in,
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("scans s", [
            's.*'
        ], $where, [
            'table_joins' => [
                "JOIN sources src ON src.id=s.src_id"
            ],
            'order' => 's.file_name'
        ]);

        $scan_rows = $this->help->execute();
        if (isset($scan_rows['id'])) {
            $scan_rows = [
                0 => $scan_rows
            ];
        }
        if (is_array($scan_rows) && count($scan_rows)) {
            foreach ($scan_rows as $row) {
                $src = $this->get_Sources($row['src_id']);
                if (is_array($src) && count($src) && isset($src[0]) && is_a($src[0], 'source')) {
                    $src = $src[0];
                } else {
                    continue;
                }

                $ste = $this->get_STE($intSTE);
                if (is_array($ste) && count($ste) && isset($ste[0]) && is_a($ste[0], 'ste')) {
                    $ste = $ste[0];
                } else {
                    continue;
                }

                $scan = new scan($row['id'], $src, $ste, $row['itr'], $row['file_name'], $row['file_date']);
                $scan->set_Notes($row['notes']);
                $scan->set_PID($row['pid']);
                $scan->set_Start_Time($row['start_time']);
                $scan->set_Last_Update($row['last_update']);
                $scan->set_Status($row['status']);
                $scan->set_Percentage_Complete($row['perc_comp']);
                $scan->set_Last_Host($row['last_host']);
                $scan->set_Total_Host_Count($row['host_count']);

                $this->help->select("host_list hl", [
                    'hl.tgt_id',
                    't.name',
                    'hl.finding_count',
                    'hl.scanner_error',
                    'hl.notes'
                ], [
                    [
                        'field' => 'hl.scan_id',
                        'value' => $row['id']
                    ]
                ], [
                    'table_joins' => [
                        "LEFT JOIN target t ON t.id=hl.tgt_id"
                    ]
                ]);
                $hl_rows = $this->help->execute();
                if (is_array($hl_rows) && count($hl_rows) && isset($hl_rows['tgt_id'])) {
                    $hl_rows = [
                        0 => $hl_rows
                    ];
                }
                if (is_array($hl_rows) && count($hl_rows) && isset($hl_rows[0])) {
                    foreach ($hl_rows as $row) {
                        $tgt = new target($row['name']);
                        $tgt->set_ID($row['tgt_id']);
                        $tgt->set_STE_ID($intSTE);
                        $tgt->interfaces = $this->get_Interfaces($tgt->get_ID());
                        if ((bool) $row['scanner_error']) {
                            $scan->setScanError((bool) $row['scanner_error']);
                        }

                        $hl = new host_list();
                        $hl->setTargetId($tgt->get_ID());
                        $hl->setTargetName($tgt->get_Name());
                        $hl->setTargetIp($tgt->getIP());
                        $hl->setFindingCount($row['finding_count']);
                        $hl->setScanError((bool) $row['scanner_error']);
                        $hl->setScanNotes($row['notes']);

                        $scan->add_Target_to_Host_List($hl);
                    }
                }

                $ret[] = $scan;
            }
        }

        return $ret;
    }

    /**
     * Save scan data
     *
     * @param scan $new_Scan
     *            New scan to save to database
     *
     * @return integer Returns ID of new scan, or 0 if fail
     */
    public function save_Scan($new_Scan)
    {
        if (! is_a($new_Scan, "scan")) {
            return;
        }
        if (! is_a($new_Scan->get_Source(), 'source')) {
            throw (new Exception("Wrong source type " . print_r($new_Scan->get_Source(), true)));
        }
        if ($new_Scan->get_ID()) {
            $this->help->update("scans", [
                'src_id' => $new_Scan->get_Source()
                    ->get_ID(),
                'itr' => $new_Scan->get_Itr(),
                'file_date' => $new_Scan->get_File_DateTime(),
                'pid' => $new_Scan->get_PID(),
                'start_time' => $new_Scan->get_Start_Time(),
                'last_update' => $new_Scan->get_Last_Update(),
                'status' => $new_Scan->get_Status(),
                'perc_comp' => $new_Scan->get_Percentage_Complete(),
                'last_host' => $new_Scan->get_Last_Host(),
                'host_count' => $new_Scan->get_Total_Host_Count(),
                'notes' => $new_Scan->get_Notes()
            ], [
                [
                    'field' => 'id',
                    'value' => $new_Scan->get_ID()
                ]
            ]);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
            }

            $this->update_Scan_Host_List($new_Scan, $new_Scan->get_Host_List());
        } else {
            $this->help->insert("scans", [
                'src_id' => $new_Scan->get_Source()
                    ->get_ID(),
                'ste_id' => $new_Scan->get_STE()
                    ->get_ID(),
                'itr' => $new_Scan->get_Itr(),
                'file_name' => $new_Scan->get_File_Name(),
                'file_date' => $new_Scan->get_File_DateTime(),
                'pid' => $new_Scan->get_PID(),
                'start_time' => $new_Scan->get_Start_Time(),
                'last_update' => $new_Scan->get_Last_Update(),
                'status' => $new_Scan->get_Status(),
                'perc_comp' => $new_Scan->get_Percentage_Complete(),
                'last_host' => $new_Scan->get_Last_Host(),
                'host_count' => $new_Scan->get_Total_Host_Count(),
                'notes' => $new_Scan->get_Notes()
            ]);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return 0;
            }

            $new_Scan->set_ID($this->conn->insert_id);

            $this->update_Scan_Host_List($new_Scan, $new_Scan->get_Host_List());
        }
        return $new_Scan->get_ID();
    }

    /**
     * Delete a scan (associated finding data and optionally targets)
     *
     * @param integer $ste_id
     *            ST&amp;E ID where the scan exists
     * @param integer $scan_id
     *            Scan to delete from database
     * @param boolean $del_tgts
     *            Boolean to decide if we are deleting targets as well
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function delete_Scan($ste_id, $scan_id, $del_tgts = false)
    {
        $scan = $this->get_ScanData($ste_id, $scan_id);

        if (is_array($scan) && count($scan) && isset($scan[0]) && is_a($scan[0], 'scan')) {
            $scan = $scan[0];
        } elseif (! is_a($scan, 'scan')) {
            Sagacity_Error::err_handler("Failed to find Scan ($scan_id)", E_ERROR);
            return false;
        }

        $this->help->delete("finding_controls fc", [
            'fc.*'
        ], [
            [
                'field' => 'f.scan_id',
                'op' => '=',
                'value' => $scan_id
            ]
        ], [
            "JOIN findings f ON f.tgt_id = fc.tgt_id AND f.pdi_id = fc.pdi_id"
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $this->help->delete("findings", null, [
            [
                'field' => 'scan_id',
                'op' => '=',
                'value' => $scan_id
            ]
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $this->help->delete("host_list", null, [
            [
                'field' => 'scan_id',
                'op' => '=',
                'value' => $scan_id
            ]
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $this->help->delete("scans", null, [
            [
                'field' => 'id',
                'op' => '=',
                'value' => $scan_id
            ]
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        if ($del_tgts) {
            /**
             *
             * @var host_list $host
             */
            foreach ($scan->get_Host_List() as $host) {
                $this->delete_Target($host->getTargetId());
            }
        }

        return true;
    }

    /**
     * Updates the host_list field for a particular scan
     *
     * @param scan $scan
     *            Scan to update
     * @param array $host_list
     *            [optional]
     *            Formatted host list to update (default null)
     *
     * @return boolean Returns TRUE if successful, otherwise FALSEs
     */
    public function update_Scan_Host_List($scan, $host_list = null)
    {
        $this->help->delete("host_list", null, [
            [
                'field' => 'scan_id',
                'value' => $scan->get_ID()
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        $params = [];
        if (is_null($host_list)) {
            foreach ($scan->get_Host_List() as $host) {
                $params[] = [
                    $scan->get_ID(),
                    $host->getTargetId(),
                    $host->getFindingCount(),
                    $host->getScanError(),
                    $host->getScanNotes()
                ];
            }
        } else {
            foreach ($host_list as $host) {
                if (! is_a($host, 'host_list')) {
                    break;
                }
                $params[] = [
                    $scan->get_ID(),
                    $host->getTargetId(),
                    $host->getFindingCount(),
                    $host->getScanError(),
                    $host->getScanNotes()
                ];
            }
        }

        if (count($params)) {
            $this->help->extended_insert("host_list", [
                'scan_id',
                'tgt_id',
                'finding_count',
                'scanner_error',
                'notes'
            ], $params);
            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
            }
        }

        return true;
    }

    /**
     * Get the scan source data
     *
     * @param integer|string $srcID
     *            Source ID or name to grab from database
     *
     * @return source|NULL Returns source, or null if none found
     */
    public function get_Sources($srcID = null)
    {
        $where = [];
        $ret = null;

        if (! is_null($srcID)) {
            if (is_numeric($srcID)) {
                $where[] = [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $srcID
                ];
            } else {
                $where[] = [
                    'field' => 'name',
                    'op' => '=',
                    'value' => $srcID,
                    'case_insensitive' => true
                ];
            }
        }

        $this->help->select("sagacity.sources", null, $where, [
            'order' => 'name'
        ]);
        $src_rows = $this->help->execute();

        if (is_array($src_rows) && isset($src_rows['id'])) {
            $src_rows = [
                0 => $src_rows
            ];
        }

        if (is_array($src_rows) && count($src_rows) && isset($src_rows[0])) {
            foreach ($src_rows as $row) {
                $src = new source($row['id'], $row['name']);
                $src->set_Icon($row['icon']);

                $ret[] = $src;
            }
        }

        return $ret;
    }

    /**
     * Function to get the expected sources for a category
     *
     * @param ste_cat $cat
     *
     * @return array:source|array
     */
    public function get_Expected_Category_Sources($cat)
    {
        if (is_array($cat) && count($cat)) {
            $cat = $cat[0];
        }
        if (! is_a($cat, "ste_cat")) {
            return [];
        }
        $ret = [];
        $this->help->select("sagacity.sources s", [
            's.id',
            's.name',
            's.icon'
        ], [
            [
                'field' => 'cat.id',
                'op' => '=',
                'value' => $cat->get_ID()
            ]
        ], [
            'table_joins' => [
                "JOIN sagacity.ste_cat_sources src ON s.id=src.src_id",
                "JOIN sagacity.ste_cat cat ON cat.id=src.cat_id"
            ]
        ]);

        $src_arr = $this->help->execute();
        if (is_array($src_arr) && count($src_arr) && isset($src_arr['id'])) {
            $src_arr = [
                0 => $src_arr
            ];
        }

        if (is_array($src_arr) && count($src_arr) && isset($src_arr[0])) {
            foreach ($src_arr as $row) {
                $src = new source($row['id'], $row['name']);
                $icon = null;
                if ($row['icon']) {
                    $icon = str_replace(" ", "-", substr($row['icon'], 0, - 4)) . "-missing.png";
                }
                $src->set_Icon($icon);
                $ret[$src->get_ID()]['src'] = $src;
            }
        }

        return $ret;
    }

    /**
     * Find the sources that have contained this target
     *
     * @param target $tgt
     * @param array $exp_scan_srcs
     *
     * @return array:sources
     */
    public function get_Target_Scan_Sources($tgt, &$exp_scan_srcs = null)
    {
        $ret = [];
        $this->help->select("sources src", [
            "src.id",
            "src.name",
            "src.icon",
            "hl.scanner_error",
            "hl.notes",
            "hl.finding_count",
            "s.file_name"
        ], [
            [
                'field' => 'hl.tgt_id',
                'value' => $tgt->get_ID()
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN scans s ON s.src_id=src.id",
                "LEFT JOIN host_list hl ON hl.scan_id=s.id"
            ]
        ]);

        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            if (is_null($exp_scan_srcs)) {
                foreach ($rows as $row) {
                    $src = new source($row['id'], $row['name']);
                    $src->set_Icon($row['icon']);
                    $ret[$row['id']] = [
                        'src' => $src,
                        'scan_error' => (boolean) $row['scanner_error'],
                        'notes' => $row['notes'],
                        'file_name' => (!isset($ret[$row['id']]['file_name']) ? "{$row['file_name']} ({$row['finding_count']})" : "{$ret[$row['id']]['file_name']}\n{$row['file_name']} ({$row['finding_count']})")
                    ];
                }
            } else {
                foreach ($rows as $row) {
                    if (isset($exp_scan_srcs[$row['id']])) {
                        $exp_scan_srcs[$row['id']]['src']->set_Icon($row['icon']);
                        $exp_scan_srcs[$row['id']] = [
                            'scan_error' => (boolean) $row['scanner_error'],
                            'notes' => $row['notes'],
                            'file_name' => (!isset($exp_scan_srcs[$row['id']]['file_name']) ? "{$row['file_name']} ({$row['finding_count']})" : "{$exp_scan_srcs[$row['id']]['file_name']}\n{$row['file_name']} ({$row['finding_count']})")
                        ];
                    } else {
                        $src = new source($row['id'], $row['name']);
                        $src->set_Icon($row['icon']);
                        $exp_scan_srcs[$row['id']] = [
                            'src' => $src,
                            'scan_error' => (boolean) $row['scanner_error'],
                            'notes' => $row['notes'],
                            'file_name' => "{$row['file_name']} ({$row['finding_count']})"
                        ];
                    }
                }

                return $exp_scan_srcs;
            }
        }

        return $ret;
    }

    // }}}
    // {{{ SCRIPT FUNCTIONS
    /**
     * Function to get a catalog script
     *
     * @param string $file_name_in
     *            [optional]
     *            Look for a specific catalog/STIG file that is processing
     *
     * @return array:catalog_script|NULL
     */
    public function get_Catalog_Script($file_name_in = null)
    {
        $ret = [];
        $where = [];

        if (! is_null($file_name_in)) {
            $where[] = [
                'field' => 'file_name',
                'op' => '=',
                'value' => $file_name_in
            ];
        }

        $this->help->select("sagacity.catalog_scripts cs", ['c.id', 'cs.*'], $where, [
            'table_joins' => [
                "LEFT JOIN sagacity.checklist c ON c.file_name = cs.file_name"
            ],
            'order' => "FIELD(`status`, 'ERROR','RUNNING','IN QUEUE','COMPLETE'),`file_name`"
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['file_name'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows)) {
            foreach ($rows as $row) {
                $script = new catalog_script();

                $script->{'id'} = $row['id'];
                $script->file_name = $row['file_name'];
                $script->pid = $row['pid'];
                $script->start_time = new DateTime($row['start_time']);
                $script->last_update = new DateTime($row['last_update']);
                $script->status = $row['status'];
                $script->perc_comp = $row['perc_comp'];
                $script->stig_count = $row['stig_count'];

                $ret[] = $script;
            }
        }

        return $ret;
    }

    /**
     * Function to get script count
     *
     * @param string $status
     *            [optional]
     *            Return only the count for a script that is in a certain status (defaulted null)
     *
     * @return integer Returns the number of script that are in the database or count in a specific status
     */
    public function get_Catalog_Script_Count($status = null)
    {
        $where = [];
        if (! is_null($status)) {
            $where[] = [
                'field' => 'status',
                'op' => '=',
                'value' => $status
            ];

            if ($status == 'RUNNING') {
                $where[] = [
                    'field' => 'perc_comp',
                    'op' => '<',
                    'value' => 100,
                    'sql_op' => 'AND',
                    'open-paren' => true
                ];
                $where[] = [
                    'field' => 'perc_comp',
                    'op' => IS,
                    'value' => null,
                    'sql_op' => 'OR',
                    'close-paren' => true
                ];
            }
        }

        $this->help->select_count("sagacity.catalog_scripts", $where);

        if ($count = $this->help->execute()) {
            return $count;
        }

        return 0;
    }

    /**
     * Function to add new catalog parsing script
     *
     * @param string $file_name_in
     *            The catalog/STIG file that is processing
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function add_Catalog_Script($file_name_in)
    {
        $this->help->insert("sagacity.catalog_scripts", [
            'file_name' => $file_name_in
        ], true);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to update catalog script execution
     *
     * @param string $file
     *            Script to update
     * @param array $field
     *            Array with the name and value of the column to update
     *            'name' => 'pid',
     *            'value' => 1234
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function update_Catalog_Script($file, $field)
    {
        $where = array(
            array(
                'field' => 'file_name',
                'op' => '=',
                'value' => $file
            )
        );

        if ($field['name'] == 'perc_comp' && $field['value'] == 100 && isset($field['complete'])) {
            $this->help->update("sagacity.catalog_scripts", array(
                $field['name'] => $field['value'],
                'status' => 'COMPLETE',
                'last_update' => 'NOW()'
            ), $where);
        } elseif ($field['name'] == 'pid') {
            $this->help->update("sagacity.catalog_scripts", array(
                $field['name'] => $field['value'],
                'status' => 'RUNNING',
                'start_time' => 'NOW()',
                'last_update' => 'NOW()'
            ), $where);
        } else {
            $this->help->update('sagacity.catalog_scripts', array(
                $field['name'] => $field['value'],
                'last_update' => 'NOW()'
            ), $where);
        }

        if (! $this->help->execute()) {
            return false;
        }

        return true;
    }

    /**
     * Function to get the number of scripts that are currently running
     *
     * @param integer $ste
     *            ST&E to evaluate
     *
     * @return integer Returns the count of scripts that are running
     */
    public function get_Running_Script_Count($ste)
    {
        $this->help->select_count("scans", [
            [
                'field' => 'status',
                'op' => '=',
                'value' => 'RUNNING'
            ],
            [
                'field' => 'ste_id',
                'op' => '=',
                'value' => $ste,
                'sql_op' => 'AND'
            ]
        ]);

        return $this->help->execute();
    }

    /**
     * Getter function to retrieve the status of a result script
     *
     * @param int $ste_id
     * @param string $file
     *
     * @return string
     */
    public function get_Running_Script_Status($ste_id, $file)
    {
        $this->help->select("sagacity.scans", [
            'status',
            'perc_comp'
        ], [
            [
                'field' => 'ste_id',
                'op' => '=',
                'value' => $ste_id
            ],
            [
                'field' => 'file_name',
                'op' => '=',
                'value' => $file,
                'sql_op' => 'AND'
            ]
        ]);

        return $this->help->execute();
    }

    /**
     * Add a new script to the database
     *
     * @param string $file
     *            Result file name
     * @param integer $ste_id
     *            The STE ID that the script is being added to
     * @param string $type
     *            The result type
     *
     * @return boolean Return TRUE if successful, otherwise FALSE
     */
    public function add_Running_Script($file, $ste_id, $type, $location)
    {
        $existing_scan = $this->get_ScanData($ste_id, $file);

        if (is_array($existing_scan) && count($existing_scan) && isset($existing_scan[0]) && is_a($existing_scan[0], 'scan')) {
            $scan = $existing_scan[0];

            $this->help->update("scans", [
                'start_time' => 'NOW()',
                'last_update' => 'NOW()',
                'perc_comp' => 0.0
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $scan->get_ID()
                ]
            ]);
        } else {
            $type = str_replace("_", " ", $type);
            $src = $this->get_Sources($type);

            if (is_array($src) && count($src) && is_a($src[0], 'source')) {
                $src = $src[0];
            } else {
                return false;
            }

            $fd = date("Y-m-d", filemtime(TMP . "/" . $file));

            $this->help->insert("sagacity.scans", [
                'ste_id' => $ste_id,
                'src_id' => $src->get_ID(),
                'file_name' => $file,
                'file_date' => $fd,
                'start_time' => 'NOW()',
                'last_update' => 'NOW()',
                'status' => 'IN QUEUE',
                'perc_comp' => 0.0,
                'location' => $location
            ], true);
        }

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to update a running script entry to add the process ID
     *
     * @param string $file
     *            The result file to update
     * @param array $field
     *            Associative array (name,value) to know what field to update
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function update_Running_Scan($file, $field)
    {
        $where = [
            [
                'field' => 'file_name',
                'op' => '=',
                'value' => $file
            ]
        ];

        if ($field['name'] == 'perc_comp' && $field['value'] == 100 && isset($field['complete'])) {
            $this->help->update("sagacity.scans", [
                $field['name'] => $field['value'],
                'status' => 'COMPLETE',
                'last_update' => 'NOW()'
            ], $where);
        } elseif ($field['name'] == 'pid') {
            $this->help->update("sagacity.scans", [
                $field['name'] => $field['value'],
                'status' => 'RUNNING',
                'start_time' => 'NOW()',
                'last_update' => 'NOW()',
                'host_count' => 0
            ], $where);
        } elseif ($field['name'] == 'last_host') {
            $this->help->update("sagacity.scans s", [
                "s.{$field['name']}" => $field['value'],
                's.last_update' => 'NOW()',
                's.hosts_comp' => "s.`hosts_comp`+1"
            ], $where);
        } else {
            $this->help->update("sagacity.scans", [
                $field['name'] => $field['value'],
                'last_update' => 'NOW()'
            ], $where);
        }

        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
            return false;
        }
        return true;
    }

    // }}}
    // {{{ SITE CLASS FUNCTIONS
    /**
     * Get site data
     *
     * @param integer $siteID
     *            [optional]
     *            Site ID to get from database
     *
     * @return array:site Returns array of sites, or empty array if none found
     */
    public function get_Site($siteID = null)
    {
        $where = [];
        $sites = [];

        if (! is_null($siteID)) {
            if (is_numeric($siteID)) {
                $where[] = [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $siteID
                ];
            } else {
                $where = [
                    'field' => 'name',
                    'op' => '=',
                    'value' => $siteID
                ];
            }
        }

        $this->help->select("sites", null, $where, [
            'order' => 'name'
        ]);

        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $sites[] = new site($row['id'], $row['name'], $row['address'], $row['city'], $row['state'], $row['zip'], $row['country'], $row['poc_name'], $row['poc_email'], $row['poc_phone']);
            }
        }

        return $sites;
    }

    /**
     * Get a site for an ST&E
     *
     * @param integer $intSTE
     *            ID of the STE to isolate
     *
     * @return site|NULL Returns array of sites associated with a specific ST&E, or null if none found
     */
    public function get_Site_By_STE_ID($intSTE)
    {
        $this->help->select("sites s", [
            's.*'
        ], [
            [
                'field' => 'ste.id',
                'op' => '=',
                'value' => $intSTE
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN ste ON ste.site_id = s.id"
            ]
        ]);

        $row = $this->help->execute();
        if (is_array($row) && count($row) && isset($row['id'])) {
            $site = new site($row['id'], $row['name'], $row['address'], $row['city'], $row['state'], $row['zip'], $row['country'], $row['poc_name'], $row['poc_email'], $row['poc_phone']);

            return $site;
        }

        return null;
    }

    /**
     * Update or insert a site
     *
     * @param site $site_In
     *            Site to save to the database
     *
     * @return boolean|NULL Returns TRUE if successful, otherwise FALSE
     */
    public function save_Site(site $site_In)
    {
        if ($site_In->get_Id()) {
            $this->help->update("sites", [
                'name' => $site_In->get_Name(),
                'address' => $site_In->get_Address(),
                'city' => $site_In->get_City(),
                'state' => $site_In->get_State(),
                'zip' => $site_In->get_Zip(),
                'country' => $site_In->get_Country(),
                'poc_name' => $site_In->get_POC_Name(),
                'poc_email' => $site_In->get_POC_Email(),
                'poc_phone' => $site_In->get_POC_Phone()
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $site_In->get_Id()
                ]
            ]);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }

            return $site_In->get_Id();
        } else {
            $this->help->insert("sites", [
                'name' => $site_In->get_Name(),
                'address' => $site_In->get_Address(),
                'city' => $site_In->get_City(),
                'state' => $site_In->get_State(),
                'zip' => $site_In->get_Zip(),
                'country' => $site_In->get_Country(),
                'poc_name' => $site_In->get_POC_Name(),
                'poc_email' => $site_In->get_POC_Email(),
                'poc_phone' => $site_In->get_POC_Phone()
            ], true);

            if (! ($site_id = $this->help->execute())) {
                $this->help->debug(E_ERROR);
                return false;
            }

            return $site_id;
        }

        return true;
    }

    // }}}
    // {{{ SOFTWARE CLASS FUNCTIONS
    /**
     * Get software data
     *
     * @param integer|string|software $software_In
     *            Specific ID, array of software objects, or associative array to use (default null)
     * @param boolean $exact_match
     *            [optional]
     *            Perform an exact match on a CPE (default false)
     *
     * @return array:software Returns array of matching software, or empty array if none found
     */
    public function get_Software($software_In, $exact_match = false)
    {
        $ret = [];
        $cpe = null;
        $sw = null;
        $query = false;

        if (is_array($software_In)) {
            if (isset($software_In[0]) && is_a($software_In[0], 'software')) {
                $cpe = $software_In[0]->get_CPE();
            } elseif (isset($software_In[0]) && isset($software_In[0]['man'])) {
                $software_In = $software_In[0];

                $type = (isset($software_In['type']) && $software_In['type'] ? "o" : "a");
                $ver = (isset($software_In['ver']) && $software_In['ver'] ? $software_In['ver'] : "-");
                $cpe = strtolower(str_replace(array(
                    " ",
                    "(",
                    ")"
                ), array(
                    "_",
                    "%28",
                    "%29"
                ), "cpe:/{$type}:{$software_In['man']}:{$software_In['name']}:{$ver}"));
            }

            if ($cpe) {
                $this->help->select("sagacity.software", null, array(
                    array(
                        'field' => 'cpe',
                        'op' => LIKE,
                        'value' => "'%$cpe%'"
                    )
                ));
                $query = true;
            }
        } elseif (is_numeric($software_In)) {
            $this->help->select("sagacity.software", null, array(
                array(
                    'field' => 'id',
                    'op' => '=',
                    'value' => $software_In
                )
            ));
            $query = true;
        } elseif (is_string($software_In)) {
            $op = $exact_match ? '=' : LIKE;
            $field = 'cpe';
            if (strpos($software_In, "cpe:2.3") !== false) {
                $field = 'cpe23';
            }

            $exclude_r2 = null;
            if (preg_match("/windows_server_20[\d]+/", $software_In)) {
                if (! preg_match("/r2/", $software_In)) {
                    $exclude_r2 = array(
                        'field' => $field,
                        'op' => NOT_LIKE,
                        'value' => "'%r2%'",
                        'sql_op' => 'AND'
                    );
                }
            }

            $this->help->select("software", null, [
                [
                    'field' => $field,
                    'op' => $op,
                    'value' => ($op == LIKE ? "'$software_In%'" : $software_In)
                ],
                $exclude_r2
            ], [
                'order' => 'cpe'
            ]);
            $query = true;
        } elseif (is_a($software_In, 'software')) {
            $os = ($software_In->is_OS() ? "/o" : "/a");
            $man = str_replace(" ", "_", strtolower($software_In->get_Man()));
            $name = str_replace(" ", "_", strtolower($software_In->get_Name()));
            $ver = str_replace(" ", "_", strtolower($software_In->get_Version()));
            $value = "'cpe:{$os}:{$man}:{$name}:{$ver}:%'";
            $field = 'cpe';

            if (! is_null($software_In->get_CPE23())) {
                $os = substr($os, 1);
                $value = "'cpe:2.3:{$os}:{$man}:{$name}:{$ver}:%'";
                $field = 'cpe23';
            }

            $this->help->select("software", null, [
                [
                    'field' => $field,
                    'op' => LIKE,
                    'value' => $value
                ]
            ], [
                'order' => 'cpe'
            ]);
            $query = true;
        }

        if ($query) {
            $rows = $this->help->execute();
            if (isset($rows['cpe'])) {
                $rows = [
                    0 => $rows
                ];
            }

            if (is_array($rows) && count($rows) && isset($rows[0])) {
                foreach ($rows as $row) {
                    $sw = new software($row['cpe'], $row['cpe23']);
                    $sw->set_ID($row['id']);
                    $sw->set_SW_String($row['sw_string']);
                    $sw->set_Shortened_SW_String($row['short_sw_string']);

                    $ret[] = $sw;
                }
            }
        }

        return $ret;
    }
    
    /**
     * Function to retrieve a software item by using the software string
     * 
     * @param string $sw_string
     * 
     * @return software|NULL
     */
    public function get_Software_By_String($sw_string)
    {
        $ret = null;
        $this->help->select("software", null, [
            [
                'field' => 'sw_string',
                'op' => '=',
                'value' => $sw_string
            ]
        ], [
            'limit' => 1
        ]);
        $row = $this->help->execute();
        
        if(is_array($row) && count($row) && isset($row['id'])) {
            $ret = new software($row['cpe'], $row['cpe23']);
            $ret->set_ID($row['id']);
            $ret->set_SW_String($row['sw_string']);
            $ret->set_Shortened_SW_String($row['short_sw_string']);
        }
        
        return $ret;
    }

    /**
     * Function to retrieve a software item by using the CPE or CPE v2.3
     *
     * @param string $cpe_in
     *            CPE to search for
     *
     * @return software|NULL Returns software object if found, otherwise null
     */
    public function get_Software_By_CPE($cpe_in)
    {
        $field = "cpe";
        if (strpos($cpe_in, "cpe:2.3") !== false) {
            $field = "cpe23";
        }

        $this->help->select("software", null, [
            [
                'field' => $field,
                'op' => '=',
                'value' => $cpe_in
            ]
        ]);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $sw = new software($row['cpe'], $row['cpe23']);
                $sw->set_ID($row['id']);
                $sw->set_SW_String($row['sw_string']);

                return $sw;
            }
        }

        return null;
    }

    /**
     * Get the IDs of the CPEs passed in
     *
     * @param array:string $cpes
     */
    public function get_Software_Ids(array $cpes = [])
    {
        $ret = [];
        $this->help->select("software", [
            'id'
        ], [
            [
                'field' => 'cpe',
                'op' => IN,
                'value' => $cpes
            ]
        ]);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = $row['id'];
            }
        }

        return $ret;
    }

    // @TODO - Finish
    /**
     * Get a list of all software items
     *
     * @param boolean $isOS
     *            Boolean to isolate the operating systems
     * @param integer $os_ID
     *            ID of a specific software, used to select an element in the drop-down
     *
     * @return string Returns a string with the drop-down option tags
     */
    public function get_Software_List($isOS, $os_ID = null)
    {
        $ret = '<option value=0> -- Please Select An Option -- </option>';
        $sql = "SELECT `id`,`cpe`,`cpe23`,`sw_string` " . "FROM `sagacity`.`software`";

        if (! is_null($os_ID)) {
            $sql .= " WHERE `id`=" . $os_ID;
        } elseif ($isOS) {
            $sql .= " WHERE `cpe23` LIKE '%:o:%'";
        } elseif (! $isOS) {
            $sql .= " WHERE `cpe23` LIKE '%:a:%'";
        }

        // set up query to split cpe string then group by man and name
        // $sql .= " GROUP BY ";

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $sw = new software($row['cpe'], $row['cpe23']);

                $ret .= "<option value='" . $row['id'] . "'";
                if ($os_ID == $row['id']) {
                    $ret .= " selected ";
                }
                $ret .= ">" . $sw->man . " " . $sw->name . " " . $sw->ver . (! empty($sw->sp) ? "(" . $sw->sp . ")" : "") . "</option>";
            }
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }

        return $ret;
    }

    /**
     * Get array of software that a target has installed
     *
     * @param integer $tgt_id
     *            Target ID to query for
     *
     * @return array:software|NULL Returns array of software that are assigned to associated target, or null if none found
     */
    public function get_Target_Software($tgt_id)
    {
        $this->help->select("software s", [
            's.*'
        ], [
            [
                'field' => 'ts.tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN sagacity.target_software ts ON ts.sft_id=s.id"
            ]
        ]);

        $sw_arr = $this->help->execute();
        $sft = [];

        if (is_array($sw_arr) && count($sw_arr)) {
            if (isset($sw_arr['cpe'])) {
                $sw_arr = [
                    0 => $sw_arr
                ];
            }

            foreach ($sw_arr as $row) {
                $sw = new software($row['cpe'], $row['cpe23']);
                $sw->set_ID($row['id']);
                $sw->set_SW_String($row['sw_string']);
                $sw->set_Shortened_SW_String($row['short_sw_string']);

                $sft[] = $sw;
            }
        }

        return $sft;
    }

    /**
     * Update existing software or add new
     *
     * @param software $sw_in
     *            The software to save
     *
     * @return integer Returns the ID of the software that was just inserted or updated if successful, otherwise it returns 0
     */
    public function save_Software($sw_in)
    {
        if (! is_null($sw_in->get_ID())) {
            $this->help->update("sagacity.software", array(
                'cpe' => $sw_in->get_CPE(),
                'cpe23' => $sw_in->get_CPE23(),
                'sw_string' => $sw_in->get_SW_String(),
                'short_sw_string' => $sw_in->get_Shortened_SW_String()
            ), array(
                array(
                    'field' => 'id',
                    'op' => '=',
                    'value' => $sw_in->get_ID()
                )
            ));

            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
                return 0;
            }

            return $sw_in->get_ID();
        } else {
            $this->help->insert("sagacity.software", array(
                'cpe' => $sw_in->get_CPE(),
                'cpe23' => $sw_in->get_CPE23(),
                'sw_string' => $sw_in->get_SW_String(),
                'short_sw_string' => $sw_in->get_Shortened_SW_String()
            ), true);

            if (! ($sw_id = $this->help->execute())) {
                $this->help->debug(E_WARNING);
                return 0;
            }

            return $sw_id;
        }

        return 0;
    }

    /**
     * Function to retrieve an array of all the software detection regex's
     *
     * @param string $type
     *
     * @return array
     */
    public function get_Regex_Array($type)
    {
        $ret = [];
        $where = [];

        if ($type != 'os') {
            $where[] = [
                'field' => 'type',
                'op' => '=',
                'value' => $type
            ];
            $where[] = [
                'field' => 'type',
                'op' => '=',
                'value' => 'multiple',
                'sql_op' => 'OR'
            ];
        } else {
            $where[] = [
                'field' => 'type',
                'op' => LIKE,
                'value' => "'%os'"
            ];
        }

        $this->help->select("sagacity.sw_man_match", null, $where);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $tmp = [
                    'id' => $row['id'],
                    'man' => $row['man'],
                    'rgx' => $row['rgx'],
                    'name' => []
                ];

                $this->help->select("sagacity.sw_name_match", null, [
                    [
                        'field' => 'man_id',
                        'op' => '=',
                        'value' => $row['id']
                    ]
                ]);
                $name_rows = $this->help->execute();

                if (is_array($name_rows) && count($name_rows) && isset($name_rows['id'])) {
                    $name_rows = [
                        0 => $name_rows
                    ];
                }

                if (is_array($name_rows) && count($name_rows) && isset($name_rows[0])) {
                    foreach ($name_rows as $row2) {
                        $tmp['name'][$row2['id']] = array(
                            'name' => $row2['name'],
                            'man_override' => $row2['man_override'],
                            'rgx' => $row2['rgx'],
                            'name_match' => $row2['name_match'],
                            'ver_match' => $row2['ver_match'],
                            'ver' => $row2['ver'],
                            'update_match' => $row2['update_match'],
                            'is_os' => ($row2['is_os'] ? true : false),
                            'multiple' => ($row2['multiple'] ? true : false)
                        );
                    }
                }

                $ret[] = $tmp;
            }
        }

        return $ret;
    }

    // }}}
    // {{{ STE CLASS FUNCTIONS
    /**
     * Get ST&E data
     *
     * @param integer $steID
     *            ST&E ID to isolate
     *
     * @return array:ste|NULL Returns array of ste objects, or null if none found
     */
    public function get_STE($steID = null)
    {
        $where = [];
        $ret = null;

        if ($steID != null) {
            $where[] = [
                'field' => 'id',
                'op' => '=',
                'value' => $steID
            ];
        } else {
            $where[] = [
                'field' => 'primary',
                'op' => '=',
                'value' => 0
            ];
        }

        $this->help->select("ste", null, $where, [
            'order' => 'eval_start DESC'
        ]);
        $ste_rows = $this->help->execute();

        if (isset($ste_rows['id'])) {
            $ste_rows = [
                0 => $ste_rows
            ];
        }

        if (is_array($ste_rows) && count($ste_rows) && isset($ste_rows[0])) {
            foreach ($ste_rows as $row) {
                $sys = $this->get_System($row['system_id']);
                if (is_array($sys) && count($sys) && isset($sys[0]) && is_a($sys[0], 'system')) {
                    $sys = $sys[0];
                } else {
                    Sagacity_Error::err_handler("Unable to find system for ST&E ID {$row['id']}", E_ERROR);
                }
                $site = $this->get_Site($row['site_id']);
                if (is_array($site) && count($site) && isset($site[0]) && is_a($site[0], 'site')) {
                    $site = $site[0];
                } else {
                    Sagacity_Error:
                    err_handler("Unable to find site for ST&E ID {$row['id']}", E_ERROR);
                }

                $ste = new ste($row['id'], $sys, $site, $row['eval_start'], $row['eval_end'], $row['multiple'], $row['primary']);
                $ste->set_Assumptions($row['assumptions']);
                $ste->set_Conclusions($row['conclusion']);
                $ste->set_Constraints($row['constraints']);
                $ste->set_Deviations($row['deviations']);
                $ste->set_Recommendations($row['recommendations']);
                $ste->set_Residual_Risk($row['residual_risk']);
                $ste->set_Scope($row['scope']);
                $ste->set_Status($row['risk_status']);
                $ste->set_AO($row['ao']);

                $this->help->select("people p", [
                    'st.pos',
                    'p.*'
                ], [
                    [
                        'field' => 'st.ste_id',
                        'op' => '=',
                        'value' => $ste->get_ID()
                    ]
                ], [
                    'table_joins' => [
                        "JOIN ste_team st ON st.people_id=p.id"
                    ]
                ]);
                $people_rows = $this->help->execute();
                if (is_array($people_rows) && isset($people_rows['id'])) {
                    $people_rows = [
                        0 => $people_rows
                    ];
                }

                if (is_array($people_rows) && count($people_rows) && isset($people_rows[0])) {
                    foreach ($people_rows as $row2) {
                        $people = new people();
                        $people->id = $row2['id'];
                        $people->org = $row2['org'];
                        $people->name = $row2['name'];
                        $people->phone = $row2['phone'];
                        $people->position = $row2['pos'];

                        $ste->add_STE_Team_Member($people);
                    }
                }

                $ret[] = $ste;
            }
        }

        return $ret;
    }

    /**
     * Get the subsystems for a particular site
     *
     * @param ste $ste_in
     *            ST&E to get subsystems for
     *
     * @return array:ste Returns the subsystem ST&E, or empty array if none found
     */
    public function get_Subsystems($ste_in)
    {
        $this->help->select("sagacity.ste", null, array(
            array(
                'field' => 'primary',
                'op' => '=',
                'value' => $ste_in->get_ID()
            )
        ));
        $ret = [];

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = array(
                0 => $rows
            );
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = new ste($row['id'], $row['system_id'], $row['site_id'], $row['eval_start'], $row['eval_end'], $row['multiple'], $row['primary']);
            }
        }

        return $ret;
    }

    /**
     * This function returns ST&E list and creates options for a select box
     * Will organize into optgroup tags if subsystems are found
     *
     * @param boolean $select_first
     *            [optional]
     *            Force the selection of the first element in the drop-down
     *
     * @return string|NULL Returns a string of option tag elements, or null if none found
     */
    public function get_STE_List($select_first = false)
    {
        $ret = '<option value="0"' . ($select_first ? ' selected' : '') . '> -- Please Select An Option -- </option>';
        $stes = $this->get_STE();

        if (is_array($stes) && count($stes) && isset($stes['id'])) {
            $stes = [
                0 => $stes
            ];
        }

        if (is_array($stes) && count($stes) && isset($stes[0])) {
            foreach ($stes as $ste) {
                $start_str = $ste->get_Eval_Start_Date()->format('d M Y');

                $subs = $this->get_Subsystems($ste);

                if (is_array($subs) && count($subs) > 0) {
                    $ret .= "<optgroup label='{$ste->get_System()->get_Name()} {$ste->get_Site()->get_Name()}'>" . "<option value='{$ste->get_ID()}'";

                    if ((isset($_REQUEST['ste']) && $_REQUEST['ste'] == $ste->get_ID()) || (isset($_COOKIE['ste']) && $_COOKIE['ste'] == $ste->get_ID())) {
                        if (! $select_first) {
                            $ret .= " selected ";
                        }
                    }

                    $ret .= ">{$ste->get_System()->get_Name()}, {$ste->get_Site()->get_Name()}, {$start_str} ({$ste->get_ID()})</option>";

                    foreach ($subs as $sub) {
                        $ret .= "<option value='{$sub->get_ID()}'";

                        if ((isset($_REQUEST['ste']) && $_REQUEST['ste'] == $sub->get_ID()) || (isset($_COOKIE['ste']) && $_COOKIE['ste'] == $sub->get_ID())) {
                            if (! $select_first) {
                                $ret .= " selected ";
                            }
                        }

                        $ret .= ">{$sub->get_System()->get_Name()}, {$sub->get_Site()->get_Name()}, {$start_str} ({$sub->get_ID()})</option>";
                    }

                    $ret .= "</optgroup>";
                } else {
                    $ret .= "<option value='{$ste->get_ID()}'";

                    if ((isset($_REQUEST['ste']) && $_REQUEST['ste'] == $ste->get_ID()) || (isset($_COOKIE['ste']) && $_COOKIE['ste'] == $ste->get_ID())) {
                        if (! $select_first) {
                            $ret .= " selected ";
                        }
                    }

                    $ret .= ">{$ste->get_System()->get_Name()}, {$ste->get_Site()->get_Name()}, {$start_str} ({$ste->get_ID()})</option>";
                }
            }
        }

        // return the string of <option> tags
        return $ret;
    }

    /**
     * This function returns an array of ste_cat objects that are within the specified ST&amp;E
     *
     * @param integer $intSTE
     *            ST&E id to grab the categories for
     * @param mixed $intCatID
     *            [optional]
     *            ID or name of the specific Category you want to retrieve
     *
     * @return array:ste_cat Returns array of ste_cat objects that match criteria
     */
    public function get_STE_Cat_List($intSTE, $intCatID = null)
    {
        $ret = [];
        $where = [
            [
                'field' => 'ste_id',
                'op' => '=',
                'value' => $intSTE
            ]
        ];

        if (! is_null($intCatID) && is_numeric($intCatID)) {
            $where[] = [
                'field' => 'id',
                'op' => '=',
                'value' => $intCatID,
                'sql_op' => 'AND'
            ];
        } elseif (! is_null($intCatID) && is_string($intCatID)) {
            $where[] = [
                'field' => 'name',
                'op' => '=',
                'value' => $intCatID,
                'sql_op' => 'AND'
            ];
        }

        $this->help->select("ste_cat", null, $where, [
            'order' => 'name'
        ]);
        $cats = $this->help->execute();

        if (is_array($cats) && count($cats) && isset($cats['id'])) {
            $cats = [
                0 => $cats
            ];
        }

        if (is_array($cats) && count($cats) && isset($cats[0])) {
            foreach ($cats as $cat) {
                $tmp = new ste_cat($cat['id'], $cat['ste_id'], $cat['name'], $cat['analysts']);

                $this->help->select("ste_cat_sources", null, [
                    [
                        'field' => 'cat_id',
                        'op' => '=',
                        'value' => $cat['id']
                    ]
                ]);
                $srcs = $this->help->execute();
                if (is_array($srcs) && count($srcs) && isset($srcs['cat_id'])) {
                    $srcs = [
                        0 => $srcs
                    ];
                }
                if (is_array($srcs) && count($srcs) && isset($srcs[0])) {
                    foreach ($srcs as $src) {
                        $tmp->add_Source($this->get_Sources($src['src_id']));
                    }
                }

                $this->get_Cat_Count($tmp);

                $ret[] = $tmp;
            }
        }

        return $ret;
    }

    /**
     * Method to retrieve the category count data from the database for a specific category
     *
     * @param ste_cat $cat
     */
    public function get_Cat_Count(ste_cat &$cat)
    {
        $where = [];
        if ($cat->get_ID()) {
            $where[] = [
                'field' => 'cat_id',
                'op' => '=',
                'value' => $cat->get_ID()
            ];
        } else {
            $where[] = [
                'field' => 'ste_id',
                'op' => '=',
                'value' => $cat->get_STE_ID()
            ];
        }
        $this->help->select("target", [
            'cat_1',
            'cat_2',
            'cat_3',
            'closed',
            'not_applicable',
            'not_reviewed'
        ], $where);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['cat_1'])) {
            $cat->open += $rows['cat_1'] + $rows['cat_2'] + $rows['cat_3'];
            $cat->na += $rows['not_applicable'];
            $cat->nf += $rows['closed'];
            $cat->nr += $rows['not_reviewed'];
        } elseif (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $r) {
                $cat->open += $r['cat_1'] + $r['cat_2'] + $r['cat_3'];
                $cat->na += $r['not_applicable'];
                $cat->nf += $r['closed'];
                $cat->nr += $r['not_reviewed'];
            }
        }

        $cat->total = $cat->open + $cat->na + $cat->nf + $cat->nr;

        $this->help->select_count("target", $where);
        $cat->tgt_count = $this->help->execute();
    }

    /**
     * Function to get categories assigned to a ST&E
     *
     * @param integer $intSTE
     *            The ST&E ID to grab categories for
     * @param string $strName
     *            The specific name the look for
     *
     * @return array:ste_cat |NULL
     *         Returns array of ste_cat for all categories in that ST&E, or null if none found
     */
    public function get_STE_Category_List($intSTE, $strName = null)
    {
        $sql = "SELECT `id`,`ste_id`,`name`,`analysts` " . "FROM `sagacity`.`ste_cat` " . "WHERE `ste_id`=$intSTE ";

        if (! is_null($strName)) {
            $sql .= "AND `name`='" . $this->conn->real_escape_string($strName) . "' ";
        }

        $sql .= "ORDER BY `name`";
        $ret = [];

        if ($res = $this->conn->query($sql)) {
            while ($row = $res->fetch_assoc()) {
                $ret[] = new ste_cat($row['id'], $row['ste_id'], $row['name'], $row['analysts']);
            }

            return $ret;
        } else {
            Sagacity_Error::sql_handler($sql);
            error_log($this->conn->error);
        }
        return [];
    }

    /**
     * Update or insert an ST&E
     *
     * @param ste $ste_In
     *            ST&E to save to the database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_STE($ste_In)
    {
        if (! isset($_REQUEST['action'])) {
            $this->help->insert("ste", [
                'system_id' => $ste_In->get_System()
                    ->get_ID(),
                'site_id' => $ste_In->get_Site()
                    ->get_ID(),
                'eval_start' => $ste_In->get_Eval_Start_Date(),
                'eval_end' => $ste_In->get_Eval_End_Date(),
                'scope' => $ste_In->get_Scope(),
                'assumptions' => $ste_In->get_Assumptions(),
                'constraints' => $ste_In->get_Constratints(),
                'deviations' => $ste_In->get_Deviations(),
                'recommendations' => $ste_In->get_Recommendations(),
                'residual_risk' => $ste_In->get_Residual_Risk(),
                'conclusion' => $ste_In->get_Conclusions(),
                'ao' => $ste_In->get_AO()
            ]);

            $id = $this->help->execute();

            if (! $id) {
                return false;
            }

            return $id;
        } elseif ($_REQUEST['action'] == 'save-ste' && ! $ste_In->get_ID()) {
            $multiple = isset($_REQUEST['add_subsystems']) ? '1' : '0';

            $this->help->insert("ste", [
                'system_id' => $ste_In->get_System()
                    ->get_ID(),
                'site_id' => $ste_In->get_Site()
                    ->get_ID(),
                'eval_start' => $ste_In->get_Eval_Start_Date(),
                'eval_end' => $ste_In->get_Eval_End_Date(),
                'scope' => $ste_In->get_Scope(),
                'assumptions' => $ste_In->get_Assumptions(),
                'constraints' => $ste_In->get_Constraints(),
                'deviations' => $ste_In->get_Deviations(),
                'recommendations' => $ste_In->get_Recommendations(),
                'residual_risk' => $ste_In->get_Residual_Risk(),
                'conclusion' => $ste_In->get_Conclusions(),
                'ao' => $ste_In->get_AO(),
                'multiple' => $multiple,
                'primary' => 0
            ]);

            $ste_id = $this->help->execute();

            if ($ste_id) {
                $this->conn->real_query("INSERT INTO `ste_cat` (`ste_id`,`name`) " . "SELECT $ste_id,`name` FROM `category`");
            } else {
                return false;
            }

            if (isset($_REQUEST['add_subsystems'])) {
                $ins = [];

                foreach ($_REQUEST['subsystems'] as $subs) {
                    $ins[] = [
                        $subs,
                        $ste_In->get_Site()->get_ID(),
                        $ste_In->get_Eval_Start_Date(),
                        $ste_In->get_Eval_End_Date(),
                        0,
                        $ste_id
                    ];

                    $this->help->extended_insert("ste", [
                        'system_id',
                        'site_id',
                        'eval_start',
                        'eval_end',
                        'multiple',
                        'primary'
                    ], $ins);
                    $sec_ste_id = $this->help->execute();

                    if ($sec_ste_id) {
                        $this->conn->real_query("INSERT INTO `ste_cat` (`ste_id`,`name`) SELECT $sec_ste_id, `name` FROM `category`");
                    } else {
                        return false;
                    }
                }
            }

            return true;
        } elseif ($_REQUEST['action'] == 'save-ste' && $ste_In->get_ID()) {
            $this->help->update("ste", [
                'system_id' => $ste_In->get_System()
                    ->get_ID(),
                'site_id' => $ste_In->get_Site()
                    ->get_ID(),
                'eval_start' => $ste_In->get_Eval_Start_Date(),
                'eval_end' => $ste_In->get_Eval_End_Date(),
                'multiple' => (isset($_REQUEST['add_subsystems']) ? '1' : '0'),
                'scope' => $ste_In->get_Scope(),
                'assumptions' => $ste_In->get_Assumptions(),
                'constraints' => $ste_In->get_Constraints(),
                'deviations' => $ste_In->get_Deviations(),
                'recommendations' => $ste_In->get_Recommendations(),
                'residual_risk' => $ste_In->get_Residual_Risk(),
                'conclusion' => $ste_In->get_Conclusions(),
                'ao' => $ste_In->get_AO(),
                'primary' => 0
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $ste_In->get_ID()
                ]
            ]);

            if (! $this->help->execute()) {
                return false;
            }

            $this->help->update("ste", [
                'primary' => '0'
            ], [
                [
                    'field' => 'primary',
                    'op' => '=',
                    'value' => $ste_In->get_ID()
                ]
            ]);
            $this->help->execute();

            if (isset($_REQUEST['add_subsystems'])) {
                foreach ($_REQUEST['subsystems'] as $subs) {
                    $ids = explode('_', $subs);
                    $this->help->update("ste", [
                        'system_id' => $ids[0],
                        'site_id' => $ste_In->get_Site()
                            ->get_ID(),
                        'eval_start' => $ste_In->get_Eval_Start_Date(),
                        'eval_end' => $ste_In->get_Eval_End_Date(),
                        'multiple' => '0',
                        'primary' => $ste_In->get_ID()
                    ], [
                        [
                            'field' => 'id',
                            'op' => '=',
                            'value' => $ids[1]
                        ]
                    ]);

                    if (! $this->help->execute()) {
                        return false;
                    }
                }
            }

            return true;
        }

        return false;
    }

    // }}}
    // {{{ STIG CLASS FUNCTIONS
    /**
     * Get STIG data
     *
     * @param string $str_Stig_ID
     *            [optional]
     *            STIG ID to get from database (default null)
     * @param boolean $like
     *            [optional]
     *            To perform a like comparison (default false)
     *
     * @return array:stig |NULL
     *         Returns array of stigs, or null if none found
     */
    public function get_Stig($str_Stig_ID = null, $like = false)
    {
        $where = [];
        $ret = [];

        if (! is_null($str_Stig_ID)) {
            if (preg_match("/^\d\.\d{1,2}$/", $str_Stig_ID)) {
                if (strlen($str_Stig_ID) == 3) {
                    $str_Stig_ID .= "00";
                } elseif (strlen($str_Stig_ID) == 4) {
                    $str_Stig_ID .= "0";
                }
            }

            if ($like) {
                $where[] = [
                    'field' => 'stig_id',
                    'op' => LIKE,
                    'value' => "'%$str_Stig_ID%'"
                ];
            } else {
                $where[] = [
                    'field' => 'stig_id',
                    'op' => '=',
                    'value' => $str_Stig_ID
                ];
            }
        }

        $this->help->select("stigs", null, $where);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['stig_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $stig = new stig($row['pdi_id'], $row['stig_id'], $row['description']);
                $stig->set_Function($row['tweak_data']);
                $ret[] = $stig;
            }
        }

        return $ret;
    }

    /**
     * Function for retrieving the STIG by the PDI
     *
     * @param integer $pdi_id
     *            PDI ID of the stig we want to isolate
     *
     * @return stig|NULL Returns stigs, or null if none found
     */
    public function get_STIG_By_PDI($pdi_id)
    {
        $stig = null;

        $this->help->select("stigs", null, [
            [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $pdi_id
            ]
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['stig_id'])) {
            $stig = new stig($rows['pdi_id'], $rows['stig_id'], $rows['description']);
        }

        return $stig;
    }

    /**
     * Function to return possible stig functions
     *
     * @param stig $stig
     * @param target $tgt
     *
     * @return string
     */
    public function get_STIG_Function($stig, $tgt)
    {
        $ret = null;
        $chk_arr = [];
        foreach ($tgt->checklists as $chk) {
            $chk_arr[] = $chk->get_ID();
        }

        $this->help->select("pdi_checklist_lookup", [
            'tweak_data'
        ], [
            [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $stig->get_PDI_ID()
            ],
            [
                'field' => 'checklist_id',
                'op' => IN,
                'op' => $chk_arr,
                'sql_op' => 'AND'
            ],
            [
                'field' => 'tweak_data',
                'op' => IS_NOT,
                'value' => null,
                'sql_op' => 'AND'
            ]
        ]);

        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['tweak_data'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret = $row['tweak_data'];
            }
        } else {
            $this->help->debug(E_WARNING);
        }

        return $ret;
    }

    /**
     * Function to add STIG to database
     *
     * @param stig $new_Stig
     *            STIG to add to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function add_Stig($new_Stig)
    {
        $this->help->insert("sagacity.stigs", array(
            'pdi_id' => $new_Stig->get_PDI_ID(),
            'stig_id' => $new_Stig->get_ID(),
            'description' => $new_Stig->get_Description()
        ), true);

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }
        return true;
    }

    // }}}
    // {{{ SV_RULE CLASS FUNCTIONS
    /**
     * Function to get SV Rule data
     *
     * @param integer $pdi_id
     *            [optional]
     *            PDI ID (defaulted null)
     * @param string $sv_rule_id
     *            [optional]
     *            SV Rule to get from database (defaulted null)
     *
     * @return array:sv_rule|NULL Returns SV Rule, or null if none found
     */
    public function get_SV_Rule($pdi_id = null, $sv_rule_id = null)
    {
        $ret = [];
        $where = [];

        if (! is_null($pdi_id) && ! is_null($sv_rule_id)) {
            $where = [
                [
                    'field' => 'pdi_id',
                    'op' => '=',
                    'value' => $pdi_id
                ],
                [
                    'field' => 'sv_rule',
                    'op' => '=',
                    'value' => $sv_rule_id,
                    'sql_op' => 'AND'
                ]
            ];
        } elseif (! is_null($sv_rule_id)) {
            $where[] = [
                'field' => 'sv_rule',
                'op' => '=',
                'value' => $sv_rule_id
            ];
        } elseif (! is_null($pdi_id)) {
            $where[] = [
                'field' => 'pdi_id',
                'op' => '=',
                'value' => $pdi_id
            ];
        }

        $this->help->select("sv_rule", null, $where);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['pdi_id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = new sv_rule($row['pdi_id'], $row['sv_rule']);
            }
        }

        return $ret;
    }

    /**
     * Update an SV Rule
     *
     * @param sv_rule $sv_Rule
     *            Array of SV Rules to save to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_SV_Rule($sv_Rule = null)
    {
        $params = [];

        if (is_array($sv_Rule) && count($sv_Rule) && isset($sv_Rule[0]) && is_a($sv_Rule[0], 'sv_rule')) {
            foreach ($sv_Rule as $rule) {
                $params[] = [
                    $rule->get_PDI_ID(),
                    $rule->get_SV_Rule()
                ];
            }
        } elseif (is_a($sv_Rule, 'sv_rule')) {
            $params[] = [
                $sv_Rule->get_PDI_ID(),
                $sv_Rule->get_SV_Rule()
            ];
        } else {
            return false;
        }

        $this->help->extended_replace("sagacity.sv_rule", array(
            'pdi_id',
            'sv_rule'
        ), $params);

        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ SYSTEM CLASS FUNCTIONS
    /**
     * Get system data
     *
     * @param integer $systemID
     *            [optional]
     *            System ID to get from database (default null)
     *
     * @return array:system|NULL Returns array of systems, or null if none found
     */
    public function get_System($systemID = null)
    {
        $ret = [];
        $where = [];

        if (! is_null($systemID)) {
            if (is_numeric($systemID)) {
                $where[] = [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $systemID
                ];
            } else {
                $where[] = [
                    'field' => 'name',
                    'op' => '=',
                    'value' => $systemID
                ];
            }
        }

        $this->help->select("sagacity.system", null, $where, [
            'order' => 'name'
        ]);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $sys = new system($row['id'], $row['name'], $row['mac'], $row['classification']);

                $sys->set_Description($row['description']);
                $sys->set_Mitigations($row['mitigations']);
                $sys->set_Executive_Summary($row['executive_summary']);
                $sys->set_Abbreviation($row['abbr']);
                switch ($row['acred_type']) {
                    case 'diacap':
                        $sys->set_Accreditation_Type(accrediation_types::DIACAP);
                        break;
                    case 'rmf':
                        $sys->set_Accreditation_Type(accrediation_types::RMF);
                        break;
                    case 'pci':
                        $sys->set_Accreditation_Type(accrediation_types::PCI);
                        break;
                    case 'nispom':
                        $sys->set_Accreditation_Type(accrediation_types::NISPOM);
                        break;
                    case 'sox':
                        $sys->set_Accreditation_Type(accrediation_types::SOX);
                        break;
                    case 'hipaa':
                        $sys->set_Accreditation_Type(accrediation_types::HIPAA);
                        break;
                    case 'cobit':
                        $sys->set_Accreditation_Type(accrediation_types::COBIT);
                }

                $ret[] = $sys;
            }
        }

        return $ret;
    }

    /**
     * Get the system for a ST&E
     *
     * @param integer $intSTE
     *            ST&E ID to query for
     *
     * @return system|NULL Returns array of systems, or null if none found
     */
    public function get_System_By_STE_ID($intSTE)
    {
        $ret = null;
        $this->help->select("system s", [
            's.*'
        ], [
            [
                'field' => 'ste.id',
                'op' => '=',
                'value' => $intSTE
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN ste ON ste.system_id = s.id"
            ]
        ]);

        $row = $this->help->execute();
        if (is_array($row) && count($row) && isset($row['id'])) {
            $ret = new system($row['id'], $row['name'], $row['mac'], $row['classification']);

            $ret->set_Description($row['description']);
            $ret->set_Mitigations($row['mitigations']);
            $ret->set_Executive_Summary($row['executive_summary']);
            $ret->set_Abbreviation($row['abbr']);
            switch ($row['acred_type']) {
                case 'diacap':
                    $ret->set_Accreditation_Type(accrediation_types::DIACAP);
                    break;
                case 'rmf':
                    $ret->set_Accreditation_Type(accrediation_types::RMF);
                    break;
                case 'pci':
                    $ret->set_Accreditation_Type(accrediation_types::PCI);
                    break;
                case 'nispom':
                    $ret->set_Accreditation_Type(accrediation_types::NISPOM);
                    break;
                case 'sox':
                    $ret->set_Accreditation_Type(accrediation_types::SOX);
                    break;
                case 'hipaa':
                    $ret->set_Accreditation_Type(accrediation_types::HIPAA);
                    break;
                case 'cobit':
                    $ret->set_Accreditation_Type(accrediation_types::COBIT);
            }
        }

        return $ret;
    }

    /**
     * Update or insert a system
     *
     * @param system $system_In
     *            System to save to database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_System($system_In)
    {
        $acred_type = '';
        switch ($system_In->get_Accreditation_Type()) {
            case accrediation_types::DIACAP:
                $acred_type = 'diacap';
                break;
            case accrediation_types::RMF:
                $acred_type = 'rmf';
                break;
            case accrediation_types::PCI:
                $acred_type = 'pci';
                break;
            case accrediation_types::NISPOM:
                $acred_type = 'nispom';
                break;
            case accrediation_types::SOX:
                $acred_type = 'sox';
                break;
            case accrediation_types::HIPAA:
                $acred_type = 'hipaa';
                break;
            case accrediation_types::COBIT:
                $acred_type = 'cobit';
        }

        if ($system_In->get_ID()) {
            $this->help->update("sagacity.system", array(
                'name' => $system_In->get_Name(),
                'mac' => $system_In->get_MAC(),
                'classification' => $system_In->get_Classification(),
                'description' => $system_In->get_Description(),
                'mitigations' => $system_In->get_Mitigations(),
                'abbr' => $system_In->get_Abbreviation(),
                'executive_summary' => $system_In->get_Executive_Summary(),
                'acred_type' => $acred_type
            ), array(
                array(
                    'field' => 'id',
                    'op' => '=',
                    'value' => $system_In->get_ID()
                )
            ));

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }

            return $system_In->get_ID();
        } else {
            $this->help->insert("sagacity.system", array(
                'name' => $system_In->get_Name(),
                'mac' => $system_In->get_MAC(),
                'classification' => $system_In->get_Classification(),
                'description' => $system_In->get_Description(),
                'mitigations' => $system_In->get_Mitigations(),
                'abbr' => $system_In->get_Abbreviation(),
                'executive_summary' => $system_In->get_Executive_Summary(),
                'acred_type' => $acred_type
            ), true);

            if (! ($sys_id = $this->help->execute())) {
                $this->help->debug(E_ERROR);
                return false;
            }

            return $sys_id;
        }
    }

    // }}}
    // {{{ TARGET CLASS FUNCTIONS
    /**
     * Check for the presents of a target
     *
     * @param integer $ste_id
     *            STE ID
     * @param string $tgt_in
     *            Target to look for (can be IPv4, IPv6, ID, name, hostname, or FQDN)
     *
     * @return integer Returns the ID of the target if found, otherwise 0
     */
    public function check_Target($ste_id, $tgt_in)
    {
        if (preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/", $tgt_in)) {
            $this->help->select("target t", [
                't.id'
            ], [
                [
                    'field' => 'i.ipv4',
                    'op' => '=',
                    'value' => $tgt_in,
                    'open-paren' => true
                ],
                [
                    'field' => 't.name',
                    'op' => '=',
                    'value' => $tgt_in,
                    'close-paren' => true,
                    'sql_op' => 'OR'
                ],
                [
                    'field' => 't.ste_id',
                    'op' => '=',
                    'value' => $ste_id,
                    'sql_op' => 'AND'
                ]
            ], [
                'table_joins' => [
                    "LEFT JOIN interfaces i ON i.tgt_id=t.id"
                ],
                'group' => 't.id',
                'limit' => 1
            ]);
        } elseif (preg_match("/\:/", $tgt_in)) {
            $this->help->select("target t", [
                't.id'
            ], [
                [
                    'field' => 'i.ipv6',
                    'op' => '=',
                    'value' => $tgt_in
                ],
                [
                    'field' => 't.ste_id',
                    'op' => '=',
                    'value' => $ste_id,
                    'sql_op' => 'AND'
                ]
            ], [
                'table_joins' => [
                    "LEFT JOIN interfaces i ON i.tgt_id=t.id"
                ]
            ]);
        } else {
            $this->help->select("target t", [
                't.id'
            ], [
                [
                    'field' => 't.ste_id',
                    'op' => '=',
                    'value' => $ste_id
                ],
                [
                    'field' => 't.id',
                    'op' => '=',
                    'value' => $tgt_in,
                    'sql_op' => 'AND',
                    'open-paren' => true
                ],
                [
                    'field' => 't.name',
                    'op' => '=',
                    'value' => $tgt_in,
                    'sql_op' => 'OR',
                    'case_insensitive' => true
                ],
                [
                    'field' => 'i.hostname',
                    'op' => '=',
                    'value' => $tgt_in,
                    'sql_op' => 'OR',
                    'case_insensitive' => true
                ],
                [
                    'field' => 'i.fqdn',
                    'op' => '=',
                    'value' => $tgt_in,
                    'sql_op' => 'OR',
                    'case_insensitive' => true,
                    'close-paren' => true
                ]
            ], [
                'table_joins' => [
                    "LEFT JOIN interfaces i ON i.tgt_id=t.id"
                ],
                'group' => 't.id'
            ]);
        }

        $tgt = $this->help->execute();
        if (is_array($tgt) && count($tgt) && isset($tgt['id'])) {
            return $tgt['id'];
        } elseif (is_array($tgt) && count($tgt) > 1) {
            Sagacity_Error::err_handler("Return more than one target " . print_r($tgt, true), E_WARNING);
        }
        /*
         * if () {
         * print_r($tgt);
         * if (isset($tgt['id'])) {
         * return $tgt['id'];
         * }
         * }
         */
        return 0;
    }

    /**
     * Get a target by name or ID or all targets in an ST&E
     *
     * @param integer $int_STE_ID
     *            ST&E ID to get targets from
     * @param integer|string $TGT
     *            [optional]
     *            Target to specific grab (can be integer ID or name)
     *
     * @return array:target Returns array of targets
     */
    public function get_Target_Details($int_STE_ID, $TGT = null)
    {
        $ret = [];
        $where = [
            [
                'field' => 't.ste_id',
                'op' => '=',
                'value' => $int_STE_ID
            ]
        ];

        if (! is_null($TGT)) {
            if (is_numeric($TGT)) {
                $where[] = [
                    'field' => 't.id',
                    'op' => '=',
                    'value' => $TGT,
                    'sql_op' => 'AND'
                ];
            } else {
                $where[] = [
                    'field' => 't.name',
                    'op' => '=',
                    'value' => $TGT,
                    'sql_op' => 'AND',
                    'case_insensitive' => true
                ];
            }
        }

        $this->help->select("target t", null, $where);
        $tgts = $this->help->execute();

        if (isset($tgts['name'])) {
            $tgts = [
                0 => $tgts
            ];
        }

        if (is_array($tgts) && count($tgts)) {
            foreach ($tgts as $row) {
                $tgt = new target($row['name']);
                $tgt->set_ID($row['id']);
                $tgt->set_STE_ID($row['ste_id']);
                $tgt->set_Cat_ID($row['cat_id']);
                $tgt->set_OS_ID($row['os_id']);
                $tgt->set_Auto_Status_ID($row['auto_status_id']);
                $tgt->set_Man_Status_ID($row['man_status_id']);
                $tgt->set_Data_Status_ID($row['data_status_id']);
                $tgt->set_FP_Cat1_Status_ID($row['fp_cat1_status_id']);
                $tgt->set_Location($row['location']);
                $tgt->set_Source($row['source']);
                $tgt->set_Notes($row['notes']);
                $tgt->set_Missing_Patches($row['missing_patches']);
                $tgt->set_OS_String($row['os_string']);
                $tgt->set_PP_Flag($row['pp_flag']);
                $tgt->set_PP_Suspended($row['pp_off']);
                $tgt->setCat1Count($row['cat_1']);
                $tgt->setCat2Count($row['cat_2']);
                $tgt->setCat3Count($row['cat_3']);
                $tgt->setNotAFindingCount($row['closed']);
                $tgt->setNotApplicableCount($row['not_applicable']);
                $tgt->setNotReviewedCount($row['not_reviewed']);
                $tgt->classification = $row['class'];
                $tgt->software = $this->get_Target_Software($row['id']);
                $tgt->checklists = $this->get_Target_Checklists($row['id']);

                $interfaces = $this->get_Interfaces($row['id']);
                if (is_array($interfaces)) {
                    foreach ($interfaces as $int) {
                        if ($int->get_IPv4()) {
                            $tgt->interfaces["{$int->get_IPv4()}"] = $int;
                        } else {
                            $tgt->interfaces["{$int->get_IPv6()}"] = $int;
                        }
                    }
                }

                $this->get_Target_MetaData($tgt);

                $ret[] = $tgt;
            }
        }

        return $ret;
    }

    /**
     * Get the target's meta data
     *
     * @param target $tgt
     *            Target to retrieve the meta data for
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function get_Target_MetaData(&$tgt)
    {
        if (! is_a($tgt, 'target')) {
            return;
        }

        $this->help->select("target t", [
            't.id',
            'nm.*',
            'sm.*',
            'um.*'
        ], [
            [
                'field' => 't.id',
                'op' => '=',
                'value' => $tgt->get_ID()
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN target_net_meta nm ON nm.tgt_id=t.id",
                "LEFT JOIN target_sys_meta sm ON sm.tgt_id=t.id",
                "LEFT JOIN target_user_meta um ON um.tgt_id=t.id"
            ],
            'group' => 't.id'
        ]);

        $row = $this->help->execute();

        if (is_array($row) && count($row) && isset($row[0])) {
            $row = $row[0];
        }

        if (is_array($row) && count($row) && isset($row['netstat_connections'])) {
            $tgt->set_Netstat_Connections($row['netstat_connections']);
            $tgt->set_Shares($row['shares']);
            $tgt->set_Routes($row['routes']);
            $tgt->set_Firewall_Config($row['firewall_config']);
            $tgt->set_Autorun($row['autorun']);
            $tgt->set_Mounted($row['mounted']);
            $tgt->set_Process_List($row['process_list']);
            $tgt->set_Services($row['services']);
            $tgt->set_Last_Boot($row['last_boot']);
            $tgt->set_Remote_Registry($row['remote_registry']);
            $tgt->set_Copyright($row['copyrighted']);
            $tgt->set_VM(($row['is_vm'] ? true : false));
            $tgt->set_System($row['system']);
            $tgt->set_BIOS($row['bios']);
            $tgt->set_WMI_PID($row['wmi_listening_pid']);
            $tgt->set_Login($row['login']);
            $tgt->set_User_List($row['user_list']);
            $tgt->set_Last_Login($row['last_login']);
            $tgt->set_Disabled_Accts($row['disabled_accts']);
            $tgt->set_Stag_Pwds($row['stag_pwds']);
            $tgt->set_Never_Logged_In($row['never_logged_in']);
            $tgt->set_Pwds_Never_Expire($row['pwd_never_expires']);

            return true;
        }

        return false;
    }

    /**
     * Get all targets in a particular group/category
     *
     * @param integer $intCat
     *            Category to get targets from
     *
     * @return array:target|NULL Returns array of targets for selected category
     */
    public function get_Target_By_Category($intCat)
    {
        $ret = [];
        $cat = $this->get_Category($intCat);
        if (is_array($cat) && count($cat)) {
            $cat = $cat[0];
        }
        $this->help->select("target", [
            'id'
        ], [
            [
                'field' => 'cat_id',
                'op' => (is_null($intCat) ? IS : '='),
                'value' => $intCat
            ]
        ], [
            'order' => 'name'
        ]);

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = $this->get_Target_Details($cat->get_STE_ID(), $row['id'])[0];
            }
        }

        return $ret;
    }

    /**
     * Function to return all targets that are not assigned to a category
     *
     * @param int $intSTE
     *
     * @return array:target |NULL
     */
    public function get_Unassigned_Targets($intSTE)
    {
        $this->help->select("target", [
            'id'
        ], [
            [
                'field' => 'cat_id',
                'op' => IS,
                'value' => null
            ],
            [
                'field' => 'ste_id',
                'op' => '=',
                'value' => $intSTE,
                'sql_op' => 'AND'
            ]
        ], [
            'order' => 'name'
        ]);
        $ret = [];

        $rows = $this->help->execute();
        if (is_array($rows) && count($rows) && isset($rows['id'])) {
            $rows = [
                0 => $rows
            ];
        }

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[] = $this->get_Target_Details($intSTE, $row['id'])[0];
            }
        }

        return $ret;
    }

    /**
     * Get the count of all targets in an ST&E
     *
     * @param integer $intCat
     *            Category to look in
     *
     * @return integer Returns count of targets in specific category
     */
    public function get_STE_Cat_TGT_Count($intCat)
    {
        $this->help->select_count("target", [
            [
                'field' => 'cat_id',
                'op' => '=',
                'value' => $intCat
            ]
        ]);

        $count = $this->help->execute();

        if (is_numeric($count)) {
            return $count;
        }

        return 0;
    }

    /**
     * Function to retrieve list of targets from 2 ST&amp;E's
     *
     * @param ste $left_ste
     *            The left or primary ST&E to compare
     * @param ste $right_ste
     *            The right or secondary ST&E to compare
     *
     * @return array:target Returns an array of targets that are similar for both or null if it exists in one, but not the other
     */
    public function get_Target_Comparison($left_ste, $right_ste)
    {
        $left_missing_sql = "SELECT `id` FROM `sagacity`.`target` WHERE `ste_id`=" . $left_ste->get_ID() . " ORDER BY `name`";
        $right_missing_sql = "SELECT `id` FROM `sagacity`.`target` WHERE `ste_id`=" . $right_ste->get_ID() . " ORDER BY `name`";
        $ret = array(
            'left' => [],
            'right' => []
        );

        if ($res = $this->conn->query($left_missing_sql)) {
            while ($row = $res->fetch_assoc()) {
                $tgt = $this->get_Target_Details($left_ste->get_ID(), $row['id'])[0];
                $ret['left'][$tgt->get_Name()] = $tgt;
            }
        }

        if ($res = $this->conn->query($right_missing_sql)) {
            while ($row = $res->fetch_assoc()) {
                $tgt = $this->get_Target_Details($right_ste->get_ID(), $row['id'])[0];
                $ret['right'][$tgt->get_Name()] = $tgt;

                if (! isset($ret['left'][$tgt->get_Name()])) {
                    $ret['left'][$tgt->get_Name()] = null;
                }
            }
        }

        return $ret;
    }

    /**
     * Function to perform post processing on nessus scan data
     *
     * @param integer $id
     *            [optional]
     *            Specific target ID to process (default null), if null will look for all targets that need the post-processing run
     * @param integer $os_id
     *            [optional]
     *            OS ID of the target (only used when passing in a specific target)
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function post_Processing($id = null)
    {
        if (is_null($id)) {
            $this->help->select("target", [
                'id',
                'os_id'
            ], [
                [
                    'field' => 'pp_flag',
                    'op' => '=',
                    'value' => 1
                ],
                [
                    'field' => 'pp_off',
                    'op' => '=',
                    'value' => 0,
                    'sql_op' => 'AND'
                ]
            ]);
            $tgts = $this->help->execute();

            if (is_array($tgts) && count($tgts) && isset($tgts['id'])) {
                $tgts = [
                    0 => $tgts
                ];
            }

            if (is_array($tgts) && count($tgts) && isset($tgts[0])) {
                foreach ($tgts as $tgt) {
                    $this->help->query_type = db_helper::INSERT;
                    $this->help->sql        = "INSERT IGNORE INTO `target_checklist` (`tgt_id`,`chk_id`) " .
                        "SELECT {$tgt['id']},c.`id` FROM (" .
                        "SELECT chk.*,s.`id` AS 'real_sw' " .
                        "FROM `checklist` chk " .
                        "JOIN `checklist_software_lookup` csl ON csl.`chk_id`=chk.`id` " .
                        "JOIN `software` s ON csl.`sw_id`=s.`id` " .
                        "WHERE " .
                        "chk.`type` = 'manual' AND " .
                        "s.`cpe` NOT LIKE '%generic:generic%' AND " .
                        "s.`cpe` NOT LIKE '%apache:http\_server%' AND " .
                        "s.`cpe` NOT LIKE '%oracle:jre%' " .
                        "ORDER BY chk.`ver` DESC,CONVERT(chk.`release`, DECIMAL(4,2)) DESC" .
                        ") c " .
                        "JOIN `target_software` ts ON ts.`sft_id`=c.`real_sw` " .
                        "WHERE ts.`tgt_id`={$tgt['id']} " .
                        "GROUP BY c.`name`,c.`type`";
                    $this->help->execute();

                    $os = $this->get_Software($tgt['os_id']);
                    if (is_array($os) && count($os) && isset($os[0]) && is_a($os[0], 'software')) {
                        $os = $os[0];
                    }

                    // to apply JRE STIGs to correct software
                    $sw = "Unix";
                    if (strtolower($os->man) == 'microsoft' && (strtolower($os->name) == 'windows xp' || (strtolower($os->name) == 'windows-nt' && strtolower($os->ver) == 'xp'))) {
                        $sw = "WinXP";
                    } elseif (strtolower($os->man) == 'microsoft' && strtolower($os->name) == 'windows 7') {
                        $sw = "Win7";
                    }
                    $this->help->query_type = db_helper::INSERT;
                    $this->help->sql = "INSERT IGNORE INTO `target_checklist` (`tgt_id`,`chk_id`) " .
                        "SELECT '{$tgt['id']}',c.`id` FROM (" .
                        "SELECT chk.*,s.`id` as 'real_sw' " .
                        "FROM `checklist` chk " .
                        "JOIN `checklist_software_lookup` csl ON csl.`chk_id`=chk.`id` " .
                        "JOIN `software` s ON s.`id`=csl.`sw_id` " .
                        "WHERE s.`cpe` LIKE '%oracle:jre%' AND " .
                        "chk.`checklist_id` LIKE 'JRE%{$sw}%' " .
                        "ORDER BY chk.`ver` DESC,CONVERT(chk.`release`, DECIMAL(4,2)) DESC" .
                        ") c " .
                        "JOIN `target_software` ts ON ts.`sft_id`=c.`real_sw` " .
                        "WHERE ts.`tgt_id`={$tgt['id']} " .
                        "GROUP BY c.`name`,c.`type`"
                    ;
                    $this->help->execute();

                    // specific checklist assignment for Apache
                    $sw = "Unix";
                    if (strtolower($os->man) == 'microsoft') {
                        $sw = "Windows";
                    }
                    $this->help->query_type = db_helper::INSERT;
                    $this->help->sql = "INSERT IGNORE INTO `target_checklist` (`tgt_id`,`chk_id`) " .
                        "SELECT '{$tgt['id']}',c.`id` FROM (" .
                        "SELECT chk.*,s.`id` AS 'real_sw' " .
                        "FROM `checklist` chk " .
                        "JOIN `checklist_software_lookup` csl ON csl.`chk_id`=chk.`id` " .
                        "JOIN `software` s ON s.`id`=csl.`sw_id` " .
                        "WHERE s.`cpe` LIKE '%apache:http\_server%' AND " .
                        "chk.`checklist_id` LIKE 'Apache%{$sw}%' " .
                        "ORDER BY chk.`ver` DESC,CONVERT(chk.`release`,DECIMAL(4,2)) DESC" .
                        ") c " .
                        "JOIN `target_software` ts ON ts.`sft_id`=c.`real_sw` " .
                        "WHERE ts.`tgt_id`={$tgt['id']} " .
                        "GROUP BY c.`name`,c.`type`"
                    ;
                    $this->help->execute();

                    $this->help->query_type = db_helper::INSERT;
                    $this->help->sql = "INSERT IGNORE INTO `target_checklist` (`tgt_id`,`chk_id`) " .
                        "SELECT '{$tgt['id']}',c.`id` FROM (" .
                        "SELECT chk.*,csl.`sw_id` AS 'real_sw' FROM `checklist` chk " .
                        "JOIN `checklist_software_lookup` csl ON csl.`chk_id`=chk.`id` " .
                        "JOIN `software` s ON csl.`sw_id`=s.`id` " .
                        "WHERE s.`cpe` NOT LIKE '%generic:generic%' " .
                        "ORDER BY chk.`ver` DESC,CONVERT(chk.`release`, DECIMAL(4,2)) DESC" .
                        ") c " .
                        "LEFT JOIN `target` t ON c.`real_sw`=t.`os_id` " .
                        "WHERE t.`id`={$tgt['id']} " .
                        "GROUP BY c.`name`,c.`type`";
                    $this->help->execute();

                    $this->help->update("target", [
                        'pp_flag' => 0
                    ], [
                        [
                            'field' => 'id',
                            'op' => '=',
                            'value' => $tgt['id']
                        ]
                    ]);
                    $this->help->execute();

                    $this->help->query_type = db_helper::INSERT;
                    $this->help->sql = "INSERT IGNORE INTO `findings` (`tgt_id`,`pdi_id`,`findings_status_id`) " .
                        "SELECT {$tgt['id']},pcl.pdi_id,'1' " .
                        "FROM target_checklist tc " .
                        "JOIN pdi_checklist_lookup pcl ON pcl.checklist_id = tc.chk_id " .
                        "WHERE tc.tgt_id = {$tgt['id']}";
                    $this->help->execute();

                    $this->update_Target_Counts($tgt['id']);
                }
            }
        } else {
            $this->help->select("checklist c", [
                'c.*',
                "s.id AS 'sw_id'"
            ], [
                [
                    'field' => 's.cpe',
                    'op' => NOT_LIKE,
                    'value' => "'%generic:generic%'"
                ],
                [
                    'field' => 's.cpe',
                    'op' => NOT_LIKE,
                    'value' => "'%apache:http\_server%'",
                    'sql_op' => 'AND'
                ],
                [
                    'field' => 's.cpe',
                    'op' => NOT_LIKE,
                    'value' => "'%oracle:jre%'",
                    'sql_op' => 'AND'
                ]
            ], [
                'table_joins' => [
                    "JOIN checklist_software_lookup csl ON csl.chk_id=c.id",
                    "JOIN software s ON csl.sw_id=s.id"
                ],
                'order' => 'c.ver DESC,CONVERT(c.`release`, DECIMAL(4,2)) DESC'
            ]);
            $this->help->create_table("c", true);
            $this->help->execute();

            $this->help->select("c", [
                "c.id"
            ], [
                [
                    'field' => 'ts.tgt_id',
                    'op' => '=',
                    'value' => $id
                ],
                [
                    'field' => 't.pp_off',
                    'op' => '=',
                    'value' => '0',
                    'sql_op' => 'AND'
                ]
            ], [
                'table_joins' => [
                    "JOIN target_software ts ON ts.sft_id=c.sw_id",
                    "JOIN target t ON t.id=ts.tgt_id"
                ],
                'group' => 'c.name,c.type'
            ]);

            $tc_arr = [];

            $rows = $this->help->execute();
            if (is_array($rows) && count($rows) && isset($rows['id'])) {
                $rows = [
                    0 => $rows
                ];
            }

            if (is_array($rows) && count($rows) && isset($rows[0])) {
                foreach ($rows as $row) {
                    $tc_arr[] = [
                        $id,
                        $row['id']
                    ];
                }
            }

            if (count($tc_arr)) {
                $this->help->extended_insert("target_checklist", [
                    'tgt_id',
                    'chk_id'
                ], $tc_arr, true);
                $this->help->execute();
            }

            $this->help->drop("sagacity", "c", true);
            $this->help->select("checklist c", [
                'c.*',
                "s.id AS 'sw_id'"
            ], [
                [
                    'field' => 's.cpe',
                    'op' => NOT_LIKE,
                    'value' => "'%generic:generic%'"
                ]
            ], [
                'table_joins' => [
                    "JOIN checklist_software_lookup csl ON csl.chk_id=c.id",
                    "JOIN software s ON csl.sw_id=s.id"
                ],
                'order' => 'c.ver DESC,CONVERT(c.`release`, DECIMAL(4,2)) DESC'
            ]);
            $this->help->create_table("c", true);
            $this->help->execute();

            $this->help->select("c", [
                "c.id"
            ], [
                [
                    'field' => 't.id',
                    'op' => '=',
                    'value' => $id
                ],
                [
                    'field' => 't.pp_off',
                    'op' => '=',
                    'value' => '0',
                    'sql_op' => 'AND'
                ]
            ], [
                'table_joins' => [
                    "LEFT JOIN target t ON c.sw_id=t.os_id"
                ],
                'group' => 'c.name,c.type'
            ]);

            $tc_arr = [];

            $rows = $this->help->execute();
            if (is_array($rows) && count($rows) && isset($rows['id'])) {
                $rows = [
                    0 => $rows
                ];
            }

            if (is_array($rows) && count($rows) && isset($rows[0])) {
                foreach ($rows as $row) {
                    $tc_arr[] = [
                        $id,
                        $row['id']
                    ];
                }
            }

            if (count($tc_arr)) {
                $this->help->extended_insert("target_checklist", [
                    'tgt_id',
                    'chk_id'
                ], $tc_arr, true);
                $this->help->execute();
            }

            $this->help->update("target", [
                "pp_flag" => 0
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $id
                ]
            ]);
            $this->help->execute();

            $this->help->query_type = db_helper::INSERT;
            $this->help->sql = "INSERT IGNORE INTO findings (tgt_id,pdi_id,findings_status_id) " .
                "SELECT {$id},pcl.pdi_id,1 " .
                "FROM target_checklist tc " .
                "JOIN pdi_checklist_lookup pcl ON pcl.checklist_id = tc.chk_id " .
                "WHERE tc.tgt_id = {$id}";
            $this->help->execute();

            $this->update_Target_Counts($id);
        }

        return true;
    }

    /**
     * Function to update the target finding counts
     *
     * @param int $tgt_id
     */
    public function update_Target_Counts($tgt_id)
    {
        $nf = 0;
        $nr = 0;
        $na = 0;
        $cat_1 = 0;
        $cat_2 = 0;
        $cat_3 = 0;

        $this->help->select('target t', [
            "COUNT(DISTINCT(pcl.pdi_id)) AS 'pdi_count'"
        ], [
            [
                'field' => 't.id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ], [
            'table_joins' => [
                "LEFT JOIN target_checklist tc ON tc.tgt_id = t.id",
                "LEFT JOIN pdi_checklist_lookup pcl ON pcl.checklist_id = tc.chk_id",
                "LEFT JOIN findings f ON f.pdi_id = pcl.pdi_id AND f.tgt_id = t.id"
            ],
            'group' => 't.id'
        ]);
        $row = $this->help->execute();
        if (is_array($row) && count($row) && isset($row['pdi_count'])) {
            $nr = $row['pdi_count'];
        }

        $this->help->select("target t", [
            "IF(ISNULL(fs.status), 'Not Reviewed', fs.status) AS 'status'",
            "f.cat AS 'severity'",
            "COUNT(DISTINCT f.pdi_id) AS 'finding_count'"
        ], [
            [
                'field' => 't.id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ], [
            'table_joins' => [
                "JOIN target_checklist tc ON tc.tgt_id = t.id",
                "JOIN pdi_checklist_lookup pcl ON tc.chk_id = pcl.checklist_id",
                "LEFT JOIN findings f ON f.tgt_id = t.id AND f.pdi_id = pcl.pdi_id",
                "LEFT JOIN findings_status fs ON f.findings_status_id = fs.id"
            ],
            'group' => "t.id,`severity`,f.findings_status_id"
        ]);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows['status'])) {
            $nr -= $rows['finding_count'];
            switch ($rows['status']) {
                case 'Not a Finding':
                case 'False Positive':
                    $nf += $rows['finding_count'];
                    break;
                case 'Not Applicable':
                    $na += $rows['finding_count'];
                    break;
                case 'Not Reviewed':
                    $nr += $rows['finding_count'];
                    break;
                case 'Open':
                case 'Exception':
                    ${'cat_' . $rows['severity']} += $rows['finding_count'];
            }
        } elseif (is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $nr -= $row['finding_count'];
                switch ($row['status']) {
                    case 'Not a Finding':
                    case 'False Positive':
                        $nf += $row['finding_count'];
                        break;
                    case 'Not Applicable':
                        $na += $row['finding_count'];
                        break;
                    case 'Not Reviewed':
                    case 'No Data':
                        $nr += $row['finding_count'];
                        break;
                    case 'Open':
                    case 'Exception':
                        ${'cat_' . $row['severity']} += $row['finding_count'];
                }
            }
        }

        $this->help->update("target", [
            'cat_1' => $cat_1,
            'cat_2' => $cat_2,
            'cat_3' => $cat_3,
            'closed' => $nf,
            'not_reviewed' => $nr,
            'not_applicable' => $na
        ], [
            [
                'field' => 'id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        $this->help->execute();
    }

    /**
     * Update or insert a target
     *
     * @param target $tgt
     *            The target to save
     * @param boolean $pp
     *
     * @return integer Returns ID of newly added target, or 0 if fail
     */
    public function save_Target($tgt, $pp = null)
    {
        if (! is_a($tgt, 'target')) {
            Sagacity_Error::err_handler("Invalid type in db::save_Target()", E_ERROR);
        }

        if (! in_array($tgt->classification, [
            'U',
            'S',
            'FOUO'
        ])) {
            $sys = $this->get_System_By_STE_ID($tgt->get_STE_ID());
            if (is_a($sys, 'system')) {
                switch ($sys->get_Classification()) {
                    case 'Sensitive':
                        $tgt->classification = "FOUO";
                        break;
                    case 'Classified':
                        $tgt->classification = "S";
                        break;
                    default:
                        $tgt->classification = "U";
                }
            } else {
                $tgt->classification = "U";
            }
        }

        if (! $tgt->get_ID()) {
            $this->help->insert("target", [
                'ste_id' => $tgt->get_STE_ID(),
                'name' => $tgt->get_Name(),
                'cat_id' => $tgt->get_Cat_ID(),
                'os_id' => $tgt->get_OS_ID(),
                'os_string' => $tgt->get_OS_String(),
                'location' => $tgt->get_Location(),
                'auto_status_id' => $tgt->get_Auto_Status_ID(),
                'man_status_id' => $tgt->get_Man_Status_ID(),
                'data_status_id' => $tgt->get_Data_Status_ID(),
                'fp_cat1_status_id' => $tgt->get_FP_Cat1_Status_ID(),
                'pp_off' => $tgt->is_PP_Suspended(),
                'class' => $tgt->classification,
                'notes' => $tgt->get_Notes()
            ]);

            if (! $this->help->execute()) {
                Sagacity_Error::err_handler("Failed to insert target {$tgt->get_Name()}", E_WARNING);
                $this->help->debug(E_ERROR);
            }

            $this->help->select("target", [
                'id'
            ], [
                [
                    'field' => 'ste_id',
                    'op' => '=',
                    'value' => $tgt->get_STE_ID()
                ],
                [
                    'field' => 'name',
                    'op' => '=',
                    'value' => $tgt->get_Name(),
                    'sql_op' => 'AND'
                ]
            ]);
            $tmp = $this->help->execute();
            if (is_array($tmp) && count($tmp) && isset($tmp['id'])) {
                $tgt->set_ID($tmp['id']);
            } else {
                Sagacity_Error::err_handler("Failure retrieving the target that was just saved {$tgt->get_Name()}", E_ERROR);
            }
        } else {
            $exist_tgt = $this->get_Target_Details($tgt->get_STE_ID(), $tgt->get_ID());
            if (is_array($exist_tgt) && count($exist_tgt) && isset($exist_tgt[0]) && is_a($exist_tgt[0], 'target')) {
                $exist_tgt = $exist_tgt[0];
                if ($exist_tgt->get_OS_ID() <= 2 && $tgt->get_OS_ID() <= 2) {
                    $os_id = $exist_tgt->get_OS_ID();
                    $os_string = $exist_tgt->get_OS_String();
                } elseif ($exist_tgt->get_OS_ID() > 2 && $tgt->get_OS_ID() <= 2) {
                    $os_id = $exist_tgt->get_OS_ID();
                    $os_string = $exist_tgt->get_OS_String();
                } elseif ($exist_tgt->get_OS_ID() <= 2 && $tgt->get_OS_ID() > 2) {
                    $os_id = $tgt->get_OS_ID();
                    $os_string = $tgt->get_OS_String();
                } else {
                    $os_id = $tgt->get_OS_ID();
                    $os_string = $tgt->get_OS_String();
                }
            } else {
                $os_id = $tgt->get_OS_ID();
                $os_string = $tgt->get_OS_String();
            }

            $this->help->update("target", [
                'name' => $tgt->get_Name(),
                'os_id' => $os_id,
                'os_string' => $os_string,
                'cat_id' => $tgt->get_Cat_ID(),
                'location' => $tgt->get_Location(),
                'auto_status_id' => $tgt->get_Auto_Status_ID(),
                'man_status_id' => $tgt->get_Man_Status_ID(),
                'data_status_id' => $tgt->get_Data_Status_ID(),
                'fp_cat1_status_id' => $tgt->get_FP_Cat1_Status_ID(),
                'missing_patches' => $tgt->get_Missing_Patches(),
                'class' => $tgt->classification,
                'pp_flag' => $tgt->is_PP_Flag_Set(),
                'pp_off' => $tgt->is_PP_Suspended(),
                'notes' => $tgt->get_Notes()
            ], [
                [
                    'field' => 'id',
                    'op' => '=',
                    'value' => $tgt->get_ID()
                ]
            ]);

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return 0;
            }
        }

        if (is_array($tgt->interfaces) && count($tgt->interfaces)) {
            $this->save_Target_Interfaces($tgt);
        }

        if (is_array($tgt->software) && count($tgt->software)) {
            $this->save_Target_Software($tgt);
        } else {
            $this->delete_Target_Software($tgt);
        }

        if (is_array($tgt->checklists) && count($tgt->checklists)) {
            $this->save_Target_Checklists($tgt);
        } else {
            $this->delete_Target_Checklists($tgt);
        }

        if ($pp === null) {
            if (! $tgt->is_PP_Suspended()) {
                $this->post_Processing($tgt->get_ID());
            } else {
                $this->update_Target_Counts($tgt->get_ID());
            }
        } else {
            if ($pp === true) {
                $this->post_Processing($tgt->get_ID());
            } else {
                $this->update_Target_Counts($tgt->get_ID());
            }
        }

        $this->help->replace("target_net_meta", [
            'tgt_id' => $tgt->get_ID(),
            'netstat_connections' => $tgt->get_Netstat_Connections(),
            'shares' => $tgt->get_Shares(),
            'routes' => $tgt->get_Routes(),
            'firewall_config' => $tgt->get_Firewall_Config()
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
        }

        $this->help->replace("target_sys_meta", [
            'tgt_id' => $tgt->get_ID(),
            'mounted' => $tgt->get_Mounted(),
            'process_list' => $tgt->get_Process_List(),
            'autorun' => $tgt->get_Autorun(),
            'services' => $tgt->get_Services(),
            'last_boot' => (is_a($tgt->get_Last_Boot(), 'DateTime') ? $tgt->get_Last_Boot() : null),
            'remote_registry' => $tgt->get_Remote_Registry(),
            'copyrighted' => $tgt->get_Copyright(),
            'is_vm' => $tgt->is_VM(),
            'system' => $tgt->get_System(),
            'bios' => $tgt->get_BIOS(),
            'wmi_listening_pid' => $tgt->get_WMI_PID()
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
        }

        $this->help->replace("target_user_meta", [
            'tgt_id' => $tgt->get_ID(),
            'login' => $tgt->get_Login(),
            'user_list' => $tgt->get_User_List(),
            'last_login' => $tgt->get_Last_Login(),
            'disabled_accts' => $tgt->get_Disabled_Accts(),
            'stag_pwds' => $tgt->get_Stag_Pwds(),
            'never_logged_in' => $tgt->get_Never_Logged_In(),
            'pwd_never_expires' => $tgt->get_Pwds_Never_Expire()
        ]);

        if (! $this->help->execute()) {
            $this->help->debug(E_WARNING);
        }

        return $tgt->get_ID();
    }

    /**
     * Function to save the checklists that are assigned to a target
     *
     * @param target $tgt
     *            Target
     * @param array:checklist $checklists
     *            [optional]
     *            Array of checklists to assign to target (if null, uses $tgt->checklists value)
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Target_Checklists($tgt, $checklists = null)
    {
        $this->help->delete("target_checklist", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt->get_ID()
            ]
        ]);
        $this->help->execute();

        /** @var checklist $chk */
        $chk_arr = [];
        if (is_array($checklists) && count($checklists) && isset($checklists[0]) && is_a($checklists[0], 'checklist')) {
            foreach ($checklists as $chk) {
                $chk_arr[] = [
                    $tgt->get_ID(),
                    $chk->get_ID()
                ];
            }
        } else {
            foreach ($tgt->checklists as $chk) {
                $chk_arr[] = [
                    $tgt->get_ID(),
                    $chk->get_ID()
                ];
            }
        }

        if (count($chk_arr)) {
            $this->help->extended_insert("target_checklist", [
                'tgt_id',
                'chk_id'
            ], $chk_arr, true);
            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
                return false;
            }
        }

        return true;
    }

    /**
     * Function to save the software installed on the target
     *
     * @param target $tgt
     *            The target that the software is installed on
     * @param array:software $software
     *            [optional]
     *            Array of software that are installed on the target (if null uses the $tgt->software)
     *
     * @return boolean
     */
    public function save_Target_Software($tgt, $software = null)
    {
        $this->help->delete("target_software", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt->get_ID()
            ]
        ]);
        $this->help->execute();

        $sw_arr = [];
        if (is_array($software) && count($software) && isset($software[0]) && is_a($software[0], 'software')) {
            foreach ($software as $sw) {
                $sw_arr[] = [
                    $tgt->get_ID(),
                    $sw->get_ID(),
                    $sw->get_Shortened_SW_String()
                ];
            }
        } else {
            foreach ($tgt->software as $sw) {
                $sw_arr[] = [
                    $tgt->get_ID(),
                    $sw->get_ID(),
                    $sw->get_Shortened_SW_String()
                ];
            }
        }

        if (count($sw_arr)) {
            $this->help->extended_insert("target_software", [
                'tgt_id',
                'sft_id',
                'sw_string'
            ], $sw_arr, true);
            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
                return false;
            }
        }

        return true;
    }

    /**
     * Function to save the interfaces of a target
     *
     * @param target $tgt
     */
    public function save_Target_Interfaces($tgt)
    {
        if (! is_array($tgt->interfaces) || ! count($tgt->interfaces)) {
            return;
        }

        foreach ($tgt->interfaces as $int) {
            if ($int->get_ID()) {
                $this->help->update("sagacity.interfaces", array(
                    'name' => $int->get_Name(),
                    'ipv4' => $int->get_IPv4(),
                    'ipv6' => $int->get_IPv6(),
                    'hostname' => $int->get_Hostname(),
                    'fqdn' => $int->get_FQDN(),
                    'description' => $int->get_Description()
                ), array(
                    array(
                        'field' => 'id',
                        'op' => '=',
                        'value' => $int->get_ID()
                    )
                ));

                if (! $this->help->execute()) {
                    $this->help->debug(E_WARNING);
                }
            } else {
                $this->help->insert("interfaces", [
                    'tgt_id' => $tgt->get_ID(),
                    'name' => $int->get_Name(),
                    'ipv4' => $int->get_IPv4(),
                    'ipv6' => $int->get_IPv6(),
                    'hostname' => $int->get_Hostname(),
                    'fqdn' => $int->get_FQDN(),
                    'description' => $int->get_Description()
                ]);

                if (! ($int_id = $this->help->execute())) {
                    $this->help->debug(E_WARNING);
                    continue;
                }

                $int->set_ID($int_id);
            }

            $ports = [];
            if (is_array($int->get_TCP_Ports()) && count($int->get_TCP_Ports())) {
                foreach ($int->get_TCP_Ports() as $port_num => $tcp) {
                    $port_num = ($tcp->get_ID() ? $tcp->get_ID() : "(SELECT `id` FROM `sagacity`.`ports_proto_services` WHERE `port`=$port_num AND `proto`='tcp' AND `notes` NOT LIKE '%historic%' LIMIT 1)");
                    $ports[] = [
                        $int->get_ID(),
                        $port_num,
                        $tcp->get_IANA_Name(),
                        $tcp->get_Banner(),
                        $tcp->get_Notes()
                    ];
                }
            }

            if (is_array($int->get_UDP_Ports()) && count($int->get_UDP_Ports())) {
                foreach ($int->get_UDP_Ports() as $port_num => $udp) {
                    $port_num = ($udp->get_ID() ? $udp->get_ID() : "(SELECT `id` FROM `sagacity`.`ports_proto_services` WHERE `port`=$port_num AND `proto`='udp' AND `notes` NOT LIKE '%historic%' LIMIT 1)");
                    $ports[] = array(
                        $int->get_ID(),
                        $port_num,
                        $udp->get_IANA_Name(),
                        $udp->get_Banner(),
                        $udp->get_Notes()
                    );
                }
            }

            if (count($ports)) {
                $this->help->extended_insert("sagacity.pps_list", array(
                    'int_id',
                    'pps_id',
                    'name',
                    'banner',
                    'notes'
                ), $ports, true);

                if (! $this->help->execute()) {
                    $this->help->debug(E_WARNING);
                }
            }
        }
    }

    /**
     * Function to merge the secondary target into the primary target data
     *
     * @param int $ste_id
     *            ID of the ST&E both targets are in
     * @param int $pri_tgt_id
     *            ID of the primary target
     * @param int $sec_tgt_id
     *            ID of the secondary target (will be deleted after complete)
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function merge_Target($ste_id, $pri_tgt_id, $sec_tgt_id)
    {
        // update the primary target checklists to add any that are in the secondary that are not already in the primary
        $this->help->select("sagacity.target_checklist", [
            'chk_id'
        ], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $pri_tgt_id
            ]
        ]);
        $tcs = $this->help->execute();
        if (is_array($tcs) && count($tcs) && isset($tcs['chk_id'])) {
            $tcs = [
                0 => $tcs
            ];
        }
        $pri_tcs = [];
        if (is_array($tcs) && count($tcs)) {
            foreach ($tcs as $tc) {
                if (isset($tc['chk_id']) && is_numeric($tc['chk_id'])) {
                    $pri_tcs[] = $tc['chk_id'];
                }
            }
        }
        if (count($pri_tcs)) {
            $this->help->update("sagacity.target_checklist", [
                'tgt_id' => $pri_tgt_id
            ], [
                [
                    'field' => 'tgt_id',
                    'op' => '=',
                    'value' => $sec_tgt_id
                ],
                [
                    'field' => 'chk_id',
                    'op' => NOT_IN,
                    'value' => $pri_tcs,
                    'sql_op' => 'AND'
                ]
            ]);
            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
                return false;
            }
        }

        // update the primary target software to add any that are in the secondary that are not already in the primary
        $this->help->select("sagacity.target_software", [
            'sft_id'
        ], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $pri_tgt_id
            ]
        ]);
        $tss = $this->help->execute();
        if (is_array($tss) && count($tss) && isset($tss['sft_id'])) {
            $tss = [
                0 => $tss
            ];
        }
        $pri_tss = [];
        if (is_array($tss) && count($tss)) {
            foreach ($tss as $ts) {
                if (isset($ts['sft_id']) && is_numeric($ts['sft_id'])) {
                    $pri_tss[] = $ts['sft_id'];
                }
            }
        }
        if (count($pri_tss)) {
            $this->help->update("sagacity.target_software", [
                'tgt_id' => $pri_tgt_id
            ], [
                [
                    'field' => 'tgt_id',
                    'op' => '=',
                    'value' => $sec_tgt_id
                ],
                [
                    'field' => 'sft_id',
                    'op' => NOT_IN,
                    'value' => $pri_tss,
                    'sql_op' => 'AND'
                ]
            ]);
            if (! $this->help->execute()) {
                $this->help->debug(E_WARNING);
            }
        }

        // delete any remaining checklists from the secondary
        $this->delete_Target_Checklists($sec_tgt_id);

        // delete any remaining software from the secondary
        $this->delete_Target_Software($sec_tgt_id);

        // need to clear this up...
        // check on PDI, and status, deconflict different statuses
        $pri_tgt = $this->get_Target_Details($ste_id, $pri_tgt_id)[0];
        $sec_tgt = $this->get_Target_Details($ste_id, $sec_tgt_id)[0];
        $sec_findings = $this->get_Finding($sec_tgt);
        foreach ($sec_findings as $key => $find) {
            $stig = $this->get_STIG_By_PDI($find->get_PDI_ID());
            $pri_find = $this->get_Finding($pri_tgt, $stig);

            if (is_array($pri_find) && count($pri_find) && isset($pri_find[0])) {
                $pri_find = $pri_find[0];
                if ($pri_find->get_Finding_Status() != $find->get_Finding_Status()) {
                    $pri_find->set_Finding_Status_By_String($pri_find->get_Deconflicted_Status($find->get_Finding_Status_String()));
                    $pri_find->prepend_Notes("Merge target-different status");
                }

                if ($find->get_Notes()) {
                    $pri_find->append_Notes($find->get_Notes(), true);
                }

                $this->help->update("sagacity.findings", [
                    'findings_status_id' => $pri_find->get_Finding_Status(),
                    'notes' => $pri_find->get_Notes()
                ], [
                    [
                        'field' => 'id',
                        'op' => '=',
                        'value' => $pri_find->get_ID()
                    ]
                ]);
            } else {
                $sec_findings[$key]->set_Tgt_ID($pri_tgt_id);
                $pri_find = $sec_findings[$key];

                $this->help->update("sagacity.findings", [
                    'tgt_id' => $pri_find->get_Tgt_ID()
                ], [
                    [
                        'field' => 'tgt_id',
                        'op' => '=',
                        'value' => $sec_tgt_id
                    ],
                    [
                        'field' => 'pdi_id',
                        'op' => '=',
                        'value' => $pri_find->get_PDI_ID(),
                        'sql_op' => 'AND'
                    ]
                ]);
            }

            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
            }
        }

        $this->delete_Target_Findings($sec_tgt_id);

        // update host_list
        $this->help->select("sagacity.host_list", [
            'scan_id'
        ], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $pri_tgt_id
            ]
        ]);
        $scan_ids = $this->help->execute();
        if (is_array($scan_ids) && count($scan_ids) && isset($scan_ids['scan_id'])) {
            $scan_ids = array(
                0 => $scan_ids
            );
        }

        if (is_array($scan_ids) && count($scan_ids) && isset($scan_ids[0])) {
            foreach ($scan_ids as $scan) {
                $this->help->select_count("sagacity.host_list", [
                    [
                        'field' => 'tgt_id',
                        'op' => '=',
                        'value' => $sec_tgt_id
                    ],
                    [
                        'field' => 'scan_id',
                        'op' => '=',
                        'value' => $scan['scan_id'],
                        'sql_op' => 'AND'
                    ]
                ]);

                if ($this->help->execute()) {
                    $this->help->delete("sagacity.host_list", null, [
                        [
                            'field' => 'tgt_id',
                            'op' => '=',
                            'value' => $sec_tgt_id
                        ],
                        [
                            'field' => 'scan_id',
                            'op' => '=',
                            'value' => $scan['scan_id'],
                            'sql_op' => 'AND'
                        ]
                    ]);
                    $this->help->execute();
                }
            }
        }
        $this->help->update("sagacity.host_list", [
            'tgt_id' => $pri_tgt_id
        ], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $sec_tgt_id
            ]
        ]);
        $this->help->execute();

        // reassign the secondary pps to the primary
        $sec_int = $this->get_Interfaces($sec_tgt_id);

        foreach ($sec_int as $int) {
            if ($int->get_IPv6()) {
                $pri_int = $this->get_Interface_By_IP($pri_tgt_id, $int->get_IPv6());
            } else {
                $pri_int = $this->get_Interface_By_IP($pri_tgt_id, $int->get_IPv4());
            }

            if (is_null($pri_int)) {
                // add the interface by updating the tgt_id pointer
                $this->help->update('sagacity.interfaces', [
                    'tgt_id' => $pri_tgt_id
                ], [
                    [
                        'field' => 'id',
                        'op' => '=',
                        'value' => $int->get_ID()
                    ]
                ]);
                $this->help->execute();
            } else {
                // loop through tcp/udp port list to see if we need to update those
                foreach ($int->get_TCP_Ports() as $tcp) {
                    if (! $pri_int->get_TCP_Port_By_Port_Number($tcp->get_Port())) {
                        $this->help->update("sagacity.pps_list", array(
                            'int_id' => $pri_int->get_ID()
                        ), array(
                            array(
                                'field' => 'int_id',
                                'op' => '=',
                                'value' => $int->get_ID()
                            ),
                            array(
                                'field' => 'pps_id',
                                'op' => '=',
                                'value' => $tcp->get_ID(),
                                'sql_op' => 'AND'
                            )
                        ));
                        $this->help->execute();
                    }
                }

                foreach ($int->get_UDP_Ports() as $udp) {
                    if (! $pri_int->get_UDP_Port_By_Port_Number($udp->get_Port())) {
                        $this->help->update("sagacity.pps_list", array(
                            'int_id' => $pri_int->get_ID()
                        ), array(
                            array(
                                'field' => 'int_id',
                                'op' => '=',
                                'value' => $int->get_ID()
                            ),
                            array(
                                'field' => 'pps_id',
                                'op' => '=',
                                'value' => $udp->get_ID(),
                                'sql_op' => 'AND'
                            )
                        ));
                        $this->help->execute();
                    }
                }
            }
        }

        $this->delete_Target($sec_tgt_id);

        return true;
    }

    /**
     * Function to delete all checklists assigned to a target
     *
     * @param target|int $tgt
     *            Target to delete all checklists from
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function delete_Target_Checklists($tgt)
    {
        if (is_a($tgt, "target")) {
            $tgt_id = $tgt->get_ID();
        } elseif (is_numeric($tgt)) {
            $tgt_id = $tgt;
        } else {
            error_log("Invalid type");
            return false;
        }
        $this->help->delete("sagacity.target_checklist", null, array(
            array(
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to delete all software assigned to a target
     *
     * @param target|int $tgt
     *            Target to delete all software from
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function delete_Target_Software($tgt)
    {
        if (is_a($tgt, 'target')) {
            $tgt_id = $tgt->get_ID();
        } elseif (is_numeric($tgt)) {
            $tgt_id = $tgt;
        } else {
            error_log("Invalid Type");
            return false;
        }

        $this->help->delete("sagacity.target_software", null, array(
            array(
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Delete a target and associated data from the database
     *
     * @param integer $tgt_id
     *            Target ID to delete from database
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function delete_Target($tgt_id)
    {
        $this->delete_Target_Checklists($tgt_id);

        $this->delete_Target_Software($tgt_id);

        $this->help->delete("finding_controls fc", [
            'fc.*'
        ], [
            [
                'field' => 'f.tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ], [
            "JOIN sagacity.findings f ON f.tgt_id = fc.tgt_id AND f.pdi_id = fc.pdi_id"
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->delete("findings", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->delete("host_list", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->select("interfaces", [
            'id'
        ], [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        $int_ids = $this->help->execute();
        if (is_array($int_ids) && count($int_ids) > 1) {
            $tmp = [];
            foreach ($int_ids as $id) {
                $tmp[] = $id['id'];
            }
            $int_ids = $tmp;
        }
        if (is_array($int_ids) && count($int_ids)) {
            $this->help->delete("pps_list", null, [
                [
                    'field' => 'int_id',
                    'op' => IN,
                    'value' => $int_ids
                ]
            ]);
            if (! $this->help->execute()) {
                $this->help->debug(E_ERROR);
                return false;
            }
        }
        $this->help->delete("interfaces", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->delete("target_net_meta", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->delete("target_sys_meta", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->delete("target_user_meta", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }
        $this->help->delete("target", null, [
            [
                'field' => 'id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);

            return false;
        }

        return true;
    }

    /**
     * Function to delete all findings for a specific target
     *
     * @param target|int $tgt
     *            ID of the target to delete the findings for
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function delete_Target_Findings($tgt)
    {
        if (is_a($tgt, 'target')) {
            $tgt_id = $tgt->get_ID();
        } elseif (is_numeric($tgt)) {
            $tgt_id = $tgt;
        } else {
            error_log("Invalid type");
            return false;
        }

        $this->help->delete("sagacity.finding_controls fc", [
            "fc.*"
        ], [
            [
                'field' => 'f.tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ], [
            "JOIN sagacity.findings f ON f.tgt_id = fc.tgt_id AND f.pdi_id = fc.pdi_id"
        ]);
        if (! $this->help->execute()) {
            error_log("Error deleting finding controls");
            $this->help->debug(E_ERROR);
            return false;
        }
        $this->help->delete("sagacity.findings", null, [
            [
                'field' => 'tgt_id',
                'op' => '=',
                'value' => $tgt_id
            ]
        ]);
        if (! $this->help->execute()) {
            error_log("Error deleting findings from findings table");
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    // }}}
    // {{{ SETTINGS FUNCTIONS
    /**
     * Function to get a setting from the database
     *
     * @param string|array:string $key
     *            [optional]
     *            If a string is passed, will return the meta_value value for the setting with that meta_key.
     *            If an array is passed, will return the key/value pair matching for each item matching e.g.
     *            [
     *            'meta_key' => 'meta_value',
     *            'meta_key2' => 'meta_value2',
     *            'meta_key3' => 'meta_value3',
     *            ...
     *            ]
     * @param mixed $default
     *            [optional]
     *            Returns this value if the key is not found in the database (defaulted to null)
     *
     * @return mixed
     */
    public function get_Settings($key = null, $default = null)
    {
        $where = [];
        if (is_array($key) && count($key)) {
            $where[] = [
                'field' => 'meta_key',
                'op' => IN,
                'value' => $key
            ];
        } elseif (is_string($key) && strlen($key)) {
            $where[] = [
                'field' => 'meta_key',
                'op' => '=',
                'value' => $key
            ];
        }

        $this->help->select("settings", [
            'meta_key',
            'meta_value'
        ], $where);
        $rows = $this->help->execute();

        if (is_array($rows) && count($rows) && isset($rows[0])) {
            $ret = [];
            foreach ($rows as $row) {
                $ret[$row['meta_key']] = $row['meta_value'];
            }
            return $ret;
        } elseif (isset($rows['meta_value'])) {
            return $rows['meta_value'];
        } else {
            return $default;
        }
    }

    /**
     * Function to set a setting in the database
     *
     * @param string $key
     * @param mixed $value
     */
    public function set_Setting($key, $value)
    {
        $ret = false;
        $this->help->select_count("sagacity.settings", [
            [
                'field' => 'meta_key',
                'op' => '=',
                'value' => $key
            ]
        ]);
        if ($this->help->execute()) {
            $this->help->update("sagacity.settings", [
                'meta_value' => $value
            ], [
                [
                    'field' => 'meta_key',
                    'op' => '=',
                    'value' => $key
                ]
            ]);
            $ret = (boolean) $this->help->execute();
        } else {
            $this->help->insert("sagacity.settings", [
                'meta_key' => $key,
                'meta_value' => $value
            ]);
            $ret = (boolean) $this->help->execute();
        }

        return $ret;
    }

    /**
     * Method to update settings values using name => value pairs
     *
     * @param array $settings
     *
     * @return boolean
     */
    public function set_Setting_Array($settings = [])
    {
        if (is_array($settings) && count($settings)) {
            foreach ($settings as $key => $val) {
                $this->help->update('settings', [
                    'meta_value' => $val
                ], [
                    [
                        'field' => 'meta_key',
                        'value' => $key
                    ]
                ]);

                if (! $this->help->execute()) {
                    return false;
                }
            }
        } else {
            return false;
        }

        return true;
    }

    // }}} END META
    // {{{ VARIOUS FUNCTIONS
    /**
     * This function returns an array of all the task statuses
     *
     * @return array:string|NULL Array of all task statuses, or null if none found
     */
    public function get_Task_Statuses()
    {
        $ret = [];
        $this->help->select("task_status");

        $rows = $this->help->execute();

        if (! is_null($rows) && is_array($rows) && count($rows) && isset($rows[0])) {
            foreach ($rows as $row) {
                $ret[$row['id']] = $row['status'];
            }
        }

        return $ret;
    }

    /**
     * This function updates the task status for a target
     *
     * @param string $strStatus
     *            Status to update
     * @param array:integer $arrTgts
     *            Array of target ids to update
     * @param int $intStatus
     *            New status id
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function update_Task_Status($strStatus, $arrTgts, $intStatus)
    {
        $field = null;
        switch ($strStatus) {
            case 'update_auto':
                $field = "auto_status_id";
                break;
            case 'update_manual':
                $field = "man_status_id";
                break;
            case 'update_data':
                $field = "data_status_id";
                break;
            case 'update_fp_cat1':
                $field = "fp_cat1_status_id";
                break;
            default:
                return false;
        }

        $this->help->update("sagacity.target", array(
            $field => $intStatus
        ), array(
            array(
                'field' => 'id',
                'op' => IN,
                'value' => $arrTgts
            )
        ));

        if (! $this->help->execute()) {
            $this->help->debug(E_ERROR);
            return false;
        }

        return true;
    }

    /**
     * Function to retrieve all helps
     *
     * @return array:string|NULL Returns array of strings with section and title data, or null if none found
     */
    public function get_All_Helps()
    {
        $this->help->select("sagacity.help", array(
            'section',
            'title'
        ), [], array(
            'order' => 'section'
        ));

        return $this->help->execute();
    }

    /**
     * Function to retrieve a help topic or function
     *
     * @param string $type
     *            Grab a specific help
     *
     * @return array:string|NULL Return array with help information, or null if none found
     */
    public function get_Help($type)
    {
        $where = [];

        if (preg_match('/(\d|[A-D]\.?)+$/', $type)) {
            $where[] = [
                'field' => 'section',
                'op' => '=',
                'value' => $type
            ];
        } else {
            if ($type != 'all') {
                $where[] = [
                    'field' => 'topic',
                    'op' => '=',
                    'value' => $type
                ];
            }
        }

        $this->help->select("help", [
            'section',
            'topic',
            'title',
            'content'
        ], $where);

        return $this->help->execute();
    }

    /**
     * Function to save the help as entered in the help_editor.php
     *
     * @param string $topic
     *            Topic of the help
     * @param string $section
     *            Section of the help
     * @param string $title
     *            Title
     * @param string $content
     *            The HTML content
     *
     * @return boolean Returns TRUE if successful, otherwise FALSE
     */
    public function save_Help($topic, $section, $title, $content)
    {
        $this->help->replace("help", array(
            'section' => $section,
            'topic' => $topic,
            'title' => $title,
            'content' => $content
        ));

        return $this->help->execute();
    }

    /**
     * Function for deleting help data
     *
     * @param string $section
     *
     * @return int
     */
    public function delete_Help($section)
    {
        $this->help->delete("help", null, array(
            array(
                'field' => 'section',
                'op' => '=',
                'value' => $section
            )
        ));

        return $this->help->execute();
    }

    /**
     * Function to check to see if the handler for the database is connected and reconnect if there is an error
     */
    public function is_Connected()
    {
        if (! mysqli_ping($this->conn)) {
            // here is the major trick, you have to close the connection (even though its not currently working) for it to recreate properly.
            $this->conn->close();
            $this->conn = new mysqli(DB_SERVER, 'web', self::decrypt_pwd(), 'sagacity');
        }
    }
    // }}}
}
