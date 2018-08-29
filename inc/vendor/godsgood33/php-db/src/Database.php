<?php

/**
 *
 */
namespace Godsgood33\Php_Db;

use Monolog\Logger;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\StreamHandler;
use Error;
use Exception;
use mysqli;

/**
 * A generic database class
 *
 * @author Ryan Prather
 */
class Database
{

    /**
     * Constant defining a SELECT query
     *
     * @var integer
     */
    const SELECT = 1;

    /**
     * Constant defining a SELECT COUNT query
     *
     * @var integer
     */
    const SELECT_COUNT = 2;

    /**
     * Constant defining a CREATE TABLE query
     *
     * @var integer
     */
    const CREATE_TABLE = 3;

    /**
     * Constant defining DROP query
     *
     * @var integer
     */
    const DROP = 4;

    /**
     * Constant defining DELETE query
     *
     * @var integer
     */
    const DELETE = 5;

    /**
     * Constant defining INSERT query
     *
     * @var integer
     */
    const INSERT = 6;

    /**
     * Constant defining REPLACE query
     *
     * @var integer
     */
    const REPLACE = 7;

    /**
     * Constant defining UPDATE query
     *
     * @var integer
     */
    const UPDATE = 8;

    /**
     * Constant defining EXTENDED INSERT query
     *
     * @var integer
     */
    const EXTENDED_INSERT = 9;

    /**
     * Constant defining EXTENDED REPLACE query
     *
     * @var integer
     */
    const EXTENDED_REPLACE = 10;

    /**
     * Constant defining EXTENDED UPDATE query
     *
     * @var integer
     */
    const EXTENDED_UPDATE = 11;

    /**
     * Constant defining ALTER TABLE query
     *
     * @var integer
     */
    const ALTER_TABLE = 12;

    /**
     * Constant defining action for alter table statement
     *
     * @var integer
     */
    const ADD_COLUMN = 1;

    /**
     * Constant defining action for alter table statement
     *
     * @var integer
     */
    const DROP_COLUMN = 2;

    /**
     * Constant defining action for alter table statement
     *
     * @var integer
     */
    const MODIFY_COLUMN = 3;

    /**
     * Constant defining a TRUNCATE TABLE query
     *
     * @var integer
     */
    const TRUNCATE = 13;

    /**
     * Global to represent an IN statement (e.g.
     * WHERE field IN (1,2))
     *
     * @var string
     */
    const IN = 'IN';

    /**
     * Global to represent a NOT IN statement (e.g.
     * WHERE field NOT IN (1,2))
     *
     * @var string
     */
    const NOT_IN = 'NOT IN';

    /**
     * Global to represent a BETWEEN statement (e.g.
     * WHERE field BETWEEN 1 and 2)
     *
     * @var string
     */
    const BETWEEN = 'BETWEEN';

    /**
     * Global to represent a LIKE statement (e.g.
     * WHERE field LIKE '%value%')
     *
     * @var string
     */
    const LIKE = 'LIKE';

    /**
     * Global to represent a NOT LIKE statement (e.g.
     * WHERE field NOT LIKE '%value%')
     *
     * @var string
     */
    const NOT_LIKE = 'NOT LIKE';

    /**
     * Global to represent an IS statement (e.g.
     * WHERE field IS NULL)
     *
     * @var string
     */
    const IS = 'IS';

    /**
     * Global to represent an IS NOT statement (e.g.
     * WHERE field IS NOT NULL)
     *
     * @var string
     */
    const IS_NOT = 'IS NOT';

    /**
     * The mysqli connection
     *
     * @var \mysqli
     */
    private $_c;

    /**
     * To store the SQL statement
     *
     * @var string
     */
    private $_sql = null;

    /**
     * A variable to store the type of query that is being run
     *
     * @var int
     */
    private $_queryType = null;

    /**
     * The result of the query
     *
     * @var mixed
     */
    private $_result = null;

    /**
     * Log level
     *
     * @var string
     */
    private $_logLevel = Logger::ERROR;

    /**
     * Variable to store the logger
     *
     * @var \Monolog\Logger
     */
    private $_logger = null;

    /**
     * Path for the logger to log the file
     *
     * @var string
     */
    private $_logPath = null;

    /**
     * Variable to decide if we need to automatically run the queries after generating them
     *
     * @var boolean
     */
    public static $autorun = false;

    /**
     * Constructor
     *
     * @param string $strLogPath
     *            [optional]
     * @param \mysqli $dbh
     *            [optional]
     *            [by ref]
     *            mysqli object to perform queries.
     */
    public function __construct($strLogPath = __DIR__, mysqli &$dbh = null)
    {
        require_once 'DBConfig.php';
        if (! is_null($dbh) && is_a($dbh, "mysqli")) {
            $this->_c = $dbh;
        } else {
            if (PHP_DB_SERVER == '{IP|hostname}' || PHP_DB_USER == '{username}' || PHP_DB_PWD == '{password}' || PHP_DB_SCHEMA == '{schema}') {
                throw new Error("Need to update DBConfig.php", E_ERROR);
            }
            $this->_c = new mysqli(PHP_DB_SERVER, PHP_DB_USER, PHP_DB_PWD, PHP_DB_SCHEMA);
        }

        if ($this->_c->connect_errno) {
            throw new Error("Could not create database class due to error {$this->_c->error}", E_ERROR);
        }

        $this->_logPath = $strLogPath;
        touch($this->_logPath . "/db.log");

        $this->_logger = new Logger('db', [
            new StreamHandler(realpath($this->_logPath . "/db.log"), $this->_logLevel)
        ]);

        if (PHP_SAPI == 'cli') {
            $stream = new StreamHandler("php://output", $this->_logLevel);
            $stream->setFormatter(new LineFormatter("%datetime% %level_name% %message%" . PHP_EOL, "H:i:s.u"));
            $this->_logger->pushHandler($stream);
        }

        $this->_logger->info("Database connected");
        $this->_logger->debug("Connection details:", [
            'Server' => PHP_DB_SERVER,
            'User'   => PHP_DB_USER,
            'Schema' => PHP_DB_SCHEMA
        ]);

        $this->setVar("time_zone", "+00:00");
        $this->setVar("sql_mode", "");
    }

    /**
     * Function to make sure that the database is connected
     *
     * @return boolean
     */
    public function isConnected()
    {
        $this->_logger->debug("Pinging server");
        return $this->_c->ping();
    }

    /**
     * Setter function for _logger
     *
     * @param Logger $log
     */
    public function setLogger(Logger $log)
    {
        $this->_logger->debug("Setting logger");
        $this->_logger = $log;
    }

    /**
     * Getter function for _logger
     *
     * @return string
     */
    public function getLogLevel()
    {
        $this->_logger->debug("Getting log level ({$this->_logLevel})");
        return $this->_logLevel;
    }

    /**
     * Function to set the log level just in case there needs to be a change to the default log level
     *
     * @param string $strLevel
     */
    public function setLogLevel($strLevel)
    {
        $this->_logger->debug("Setting log level to {$strLevel}");
        $this->_logLevel = $strLevel;

        $handles = [];

        foreach ($this->_logger->getHandlers() as $h) {
            $h->/** @scrutinizer ignore-call */
                setLevel($strLevel);
            $handles[] = $h;
        }

        $this->_logger->setHandlers($handles);
    }

    /**
     * Getter function for _queryType
     *
     * @return int
     */
    public function getQueryType()
    {
        return $this->_queryType;
    }

    /**
     * Setter function for _queryType
     *
     * @param int $qt
     */
    public function setQueryType($qt)
    {
        $this->_queryType = $qt;
    }

    /**
     * Getter function for _sql
     *
     * @return string
     */
    public function getSql()
    {
        return $this->_sql;
    }

    /**
     * Function to return the currently selected database schema
     *
     * @return string
     */
    public function getSchema()
    {
        if ($res = $this->_c->query("SELECT DATABASE()")) {
            $row = $res->fetch_row();

            $this->_logger->debug("Getting schema {$row[0]}");
            return $row[0];
        }
        return null;
    }

    /**
     * Function to set schema
     *
     * @param string $strSchema
     */
    public function setSchema($strSchema)
    {
        $this->_logger->debug("Setting schema to {$strSchema}");
        if (! $this->_c->select_db($strSchema)) {
            $this->_logger->emergency("Unknown schema {$strSchema}");
            return false;
        }
        return true;
    }

    /**
     * Method to set a MYSQL variable
     *
     * @param string $strName
     * @param string $strVal
     *
     * @return boolean
     */
    public function setVar($strName, $strVal)
    {
        if (! $strName || ! $strVal) {
            $this->_logger->debug("name or value are blank", [
                'name'  => $strName,
                'value' => $strVal
            ]);
            return false;
        }

        $this->_logger->debug("Setting {$strName} = '{$strVal}'");

        if ($this->_c->real_query("SET $strName = {$this->_escape($strVal)}")) {
            return true;
        } else {
            $this->_logger->error("Failed to set variable {$this->_c->error}");
            return false;
        }
    }

    /**
     * Function to execute the statement
     *
     * @param mixed $return
     *            [optional]
     *            MYSQLI constant to control what is returned from the mysqli_result object
     * @param string $class
     *            [optional]
     *            Class to use when returning object
     * @param string $strSql
     *            [optional]
     *            Optional SQL query
     *
     * @throws \Exception
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function execute($return = MYSQLI_ASSOC, $class = null, $strSql = null)
    {
        if (! is_null($strSql)) {
            $this->_sql = $strSql;
        }

        $query = 'SELECT';
        switch ($this->_queryType) {
            case self::SELECT_COUNT:
                $query = 'SELECT COUNT';
                break;
            case self::INSERT:
            case self::EXTENDED_INSERT:
                $query = 'INSERT';
                break;
            case self::UPDATE:
            case self::EXTENDED_UPDATE:
                $query = 'UPDATE';
                break;
            case self::REPLACE:
            case self::EXTENDED_REPLACE:
                $query = 'REPLACE';
                break;
            case self::DROP:
                $query = 'DROP';
                break;
            case self::DELETE:
                $query = 'DELETE';
                break;
            case self::CREATE_TABLE:
                $query = 'CREATE TABLE';
                break;
            case self::TRUNCATE:
                $query = 'TRUNCATE';
                break;
        }

        if (is_a($this->_c, 'mysqli')) {
            if (! $this->_c->ping()) {
                require_once 'DBConfig.php';
                $this->_c = null;
                $this->_c = new mysqli(PHP_DB_SERVER, PHP_DB_USER, PHP_DB_PWD, PHP_DB_SCHEMA);
            }
        } else {
            throw new \Error('Database was not connected', E_ERROR);
        }

        $this->_logger->info("Executing {$query} query");
        $this->_logger->debug($this->_sql);

        try {
            if (in_array($this->_queryType, [
                self::SELECT,
                self::SELECT_COUNT
            ])) {
                $this->_result = $this->_c->query($this->_sql);
                if ($this->_c->error) {
                    $this->_logger->error("There is an error {$this->_c->error}");
                    $this->_logger->debug("Errored on query", [$this->_sql]);
                    throw new Exception("There was an error {$this->_c->error}", E_ERROR);
                }
            } else {
                $this->_result = $this->_c->real_query($this->_sql);
                if ($this->_c->errno) {
                    $this->_logger->error("There was an error {$this->_c->error}");
                    $this->_logger->debug("Errored on query", [$this->_sql]);
                    throw new Exception("There was an error {$this->_c->error}", E_ERROR);
                }
            }

            if ($return == MYSQLI_OBJECT && ! is_null($class) && class_exists(/** @scrutinizer ignore-type */$class)) {
                $this->_logger->debug("Checking results for query", [
                    'class' => get_class($class)
                ]);
                $this->_result = $this->checkResults($return, $class);
            } elseif ($return == MYSQLI_OBJECT && is_null($class)) {
                $this->_logger->debug("Checking results for query", [
                    'class' => 'stdClass'
                ]);
                $this->_result = $this->checkResults($return, 'stdClass');
            } else {
                $this->_logger->debug("Checking results for query and returning associative array");
                $this->_result = $this->checkResults(MYSQLI_ASSOC);
            }
        } catch (Exception $e) {}

        return $this->_result;
    }

    /**
     * Function to check the results and return what is expected
     *
     * @param mixed $returnType
     *            [optional]
     *            Optional return mysqli_result return type
     * @param mixed $class
     *
     * @return mixed
     */
    public function checkResults($returnType = MYSQLI_ASSOC, $class = null)
    {
        $res = null;

        switch ($this->_queryType) {
            case self::SELECT_COUNT:
                if (! is_a($this->_result, 'mysqli_result')) {
                    $this->_logger->error("Error with return on query");
                    return;
                }

                if ($this->_result->num_rows == 1) {
                    $row = $this->_result->fetch_assoc();
                    if (isset($row['count'])) {
                        $this->_logger->debug("Returning SELECT_COUNT query", [
                            'count' => $row['count']
                        ]);
                        $res = $row['count'];
                    }
                } elseif ($this->_result->num_rows > 1) {
                    $this->_logger->debug("Returning SELECT_COUNT query", [
                        'count' => $this->_result->num_rows
                    ]);
                    $res = $this->_result->num_rows;
                }

                mysqli_free_result($this->_result);

                return $res;
            case self::SELECT:
                if (! is_a($this->_result, 'mysqli_result')) {
                    $this->_logger->error("Error with return on query");
                    return;
                }

                if ($returnType == MYSQLI_OBJECT && ! is_null($class) && class_exists($class)) {
                    if ($this->_result->num_rows == 1) {
                        $this->_logger->debug("Returning object from SELECT query", [
                            'type' => get_class($class)
                        ]);
                        $res = $this->_result->fetch_object($class);
                    } elseif ($this->_result->num_rows > 1) {
                        $this->_logger->debug("Returning object array from SELECT query", [
                            'type' => get_class($class)
                        ]);
                        while ($row = $this->_result->fetch_object($class)) {
                            $res[] = $row;
                        }
                    }
                } else {
                    if ($this->_result->num_rows == 1) {
                        $this->_logger->debug("Fetching results");
                        $res = $this->_result->fetch_array($returnType);
                    } elseif ($this->_result->num_rows > 1) {
                        $this->_logger->debug("Fetching results array");
                        $res = $this->fetchAll($returnType);
                    }
                }

                mysqli_free_result($this->_result);

                return $res;
            case self::INSERT:
                if ($this->_c->error) {
                    $this->_logger->error("Database Error {$this->_c->error}");
                    return 0;
                }

                if ($this->_c->insert_id) {
                    $this->_logger->debug("Insert successful returning insert_id", [
                        'id' => $this->_c->insert_id
                    ]);
                    return $this->_c->insert_id;
                } elseif ($this->_c->affected_rows) {
                    $this->_logger->debug("Insert successful return affected row count", [
                        'count' => $this->_c->affected_rows
                    ]);
                    return $this->_c->affected_rows;
                }

                $this->_logger->debug("Insert successful, but no ID so returning 1 for success");

                return 1;
            // intentional fall through
            case self::EXTENDED_INSERT:
            // intentional fall through
            case self::EXTENDED_REPLACE:
            // intentional fall through
            case self::EXTENDED_UPDATE:
            // intentional fall through
            case self::REPLACE:
            // intentional fall through
            case self::UPDATE:
            // intentional fall through
            case self::DELETE:
            // intentional fall through
            case self::ALTER_TABLE:
                if ($this->_c->error) {
                    $this->_logger->error("Database Error {$this->_c->error}");
                    return false;
                } elseif ($this->_c->affected_rows) {
                    $this->_logger->debug("Returning affected row count for {$this->_queryType}", [
                        'count' => $this->_c->affected_rows
                    ]);
                    return $this->_c->affected_rows;
                } else {
                    return true;
                }
                break;
            case self::CREATE_TABLE:
            // intentional fall through
            case self::DROP:
            // intentional fall through
            case self::TRUNCATE:
                $this->_logger->debug("Returning from {$this->_queryType}");
                return true;
        }
    }

    /**
     * Function to pass through calling the query function (used for backwards compatibility and for more complex queries that aren't currently supported)
     * Nothing is escaped
     *
     * @param string $strSql
     *            [optional]
     *            Optional query to pass in and execute
     *
     * @return \mysqli_result|boolean
     */
    public function query($strSql = null)
    {
        if (is_null($strSql)) {
            return $this->_c->query($this->_sql);
        } else {
            return $this->_c->query($strSql);
        }
    }

    /**
     * A function to build a select query
     *
     * @param string $strTableName
     *            The table to query
     * @param array|string $fields
     *            [optional]
     *            Optional array of fields to return (defaults to '*')
     * @param array $arrWhere
     *            [optional]
     *            Optional 2-dimensional array to build where clause from
     * @param array $arrFlags
     *            [optional]
     *            Optional 2-dimensional array to allow other flags
     *
     * @see Database::where()
     * @see Database::flags()
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function select($strTableName, $fields = null, $arrWhere = [], $arrFlags = [])
    {
        $this->_sql = null;
        $this->_queryType = self::SELECT;

        if (! is_null($strTableName)) {
            $this->_logger->debug("Starting SELECT query of {$strTableName}", [
                'fields' => $this->fields($fields)
            ]);
            $this->_sql = "SELECT " . $this->fields($fields) . " FROM $strTableName";
        } else {
            $this->_logger->emergency("Table name is invalid or wrong type");
            throw new Error("Table name is invalid");
        }

        if (isset($arrFlags['joins']) && is_array($arrFlags['joins']) && count($arrFlags['joins'])) {
            $this->_logger->debug("Adding joins", [
                'joins' => implode(' ', $arrFlags['joins'])
            ]);
            $this->_sql .= " " . implode(" ", $arrFlags['joins']);
        } else {
            $this->_logger->debug("No joins");
        }

        if (! is_null($arrWhere) && is_array($arrWhere) && count($arrWhere)) {
            $where_str = " WHERE";
            $this->_logger->debug("Parsing where clause and adding to query");
            foreach ($arrWhere as $x => $w) {
                $where_str .= $this->parseClause($w, $x);
            }
            if (strlen($where_str) > strlen(" WHERE")) {
                $this->_sql .= $where_str;
            }
        }

        if (is_array($arrFlags) && count($arrFlags)) {
            $this->_logger->debug("Parsing flags and adding to query", $arrFlags);
            $this->_sql .= $this->flags($arrFlags);
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build a query to check the number of rows in a table
     *
     * @param string $strTableName
     *            The table to query
     * @param array $arrWhere
     *            [optional]
     *            Optional 2-dimensional array to build where clause
     * @param array $arrFlags
     *            [optional]
     *            Optional 2-dimensional array to add flags
     *
     * @see Database::where()
     * @see Database::flags()
     *
     * @return string|NULL
     */
    public function selectCount($strTableName, $arrWhere = [], $arrFlags = [])
    {
        $this->_sql = null;
        $this->_queryType = self::SELECT_COUNT;

        if (! is_null($strTableName)) {
            $this->_sql = "SELECT COUNT(1) AS 'count' FROM $strTableName";
        } else {
            $this->_logger->emergency("Table name is invalid or wrong type");
            throw new Error("Table name is invalid");
        }

        if (isset($arrFlags['joins']) && is_array($arrFlags['joins'])) {
            $this->_sql .= " " . implode(" ", $arrFlags['joins']);
        }

        if (! is_null($arrWhere) && is_array($arrWhere) && count($arrWhere)) {
            $where_str = " WHERE";
            foreach ($arrWhere as $x => $w) {
                $where_str .= $this->parseClause($w, $x);
            }
            if (strlen($where_str) > strlen(" WHERE")) {
                $this->_sql .= $where_str;
            }
        }

        if (is_array($arrFlags) && count($arrFlags)) {
            $this->_sql .= $this->flags($arrFlags);
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build an insert query statement
     *
     * @param string $strTableName
     * @param array|string $arrParams
     * @param boolean $blnToIgnore
     *
     * @return string|NULL
     */
    public function insert($strTableName, $arrParams = null, $blnToIgnore = false)
    {
        $this->_sql = null;
        $this->_queryType = self::INSERT;

        if (! is_null($strTableName)) {
            $this->_sql = "INSERT" . ($blnToIgnore ? " IGNORE" : "") . " INTO $strTableName" . (is_array($arrParams) && count($arrParams) ? " (`" . implode("`,`", array_keys($arrParams)) . "`)" : null);
        } else {
            throw new Error("Table name is invalid");
        }

        if (is_array($arrParams) && count($arrParams)) {
            $this->_sql .= " VALUES (" . implode(",", array_map([
                $this,
                '_escape'
            ], array_values($arrParams))) . ")";
        } elseif (is_string($arrParams) && stripos($arrParams, 'SELECT') !== false) {
            $this->_sql .= " {$arrParams}";
        } else {
            throw new Error("Invalid type passed to insert " . gettype($arrParams));
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to create an extended insert query statement
     *
     * @param string $strTableName
     *            The table name that the data is going to be inserted on
     * @param array $arrFields
     *            An array of field names that each value represents
     * @param array|string $params
     *            An array of array of values or a string with a SELECT statement to populate the insert with
     * @param boolean $blnToIgnore
     *            [optional]
     *            Boolean to decide if we need to use the INSERT IGNORE INTO syntax
     *
     * @return NULL|string Returns the SQL if self::$autorun is set to false, else it returns the output from running.
     */
    public function extendedInsert($strTableName, $arrFields, $params, $blnToIgnore = false)
    {
        $this->_sql = null;
        $this->_queryType = self::EXTENDED_INSERT;

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql = "INSERT " . ($blnToIgnore ? "IGNORE " : "") . "INTO $strTableName " . "(`" . implode("`,`", $arrFields) . "`)";
        } else {
            throw new Error("Table name is invalid");
        }

        if (is_array($params) && count($params)) {
            $this->_sql .= " VALUES ";
            if (isset($params[0]) && is_array($params[0])) {
                foreach ($params as $p) {
                    if (count($p) != count($arrFields)) {
                        $this->_logger->emergency("Inconsistent number of fields to values in extended_insert", [
                            $p
                        ]);
                        throw new Error("Inconsistent number of fields in fields and values in extended_insert " . print_r($p, true));
                    }
                    $this->sql .= "(" . implode(",", array_map([$this, '_escape'], array_values($p))) . ")";

                    if ($p != end($params)) {
                        $this->_sql .= ",";
                    }
                }
            } else {
                $this->sql .= "(" . implode("),(", array_map([$this, '_escape'], array_values($params))) . ")";
            }
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Build a statement to update a table
     *
     * @param string $strTableName
     *            The table name to update
     * @param array $arrParams
     *            Name/value pairs of the field name and value
     * @param array $arrWhere
     *            [optional]
     *            Two-dimensional array to create where clause
     * @param array $arrFlags
     *            [optional]
     *            Two-dimensional array to create other flag options (joins, order, and group)
     *
     * @see Database::where()
     * @see Database::flags()
     *
     * @return NULL|string
     */
    public function update($strTableName, $arrParams, $arrWhere = [], $arrFlags = [])
    {
        $this->_sql = "UPDATE ";
        $this->_queryType = self::UPDATE;

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql .= $strTableName;

            if (isset($arrFlags['joins']) && is_array($arrFlags['joins'])) {
                $this->_sql .= " " . implode(" ", $arrFlags['joins']);
                unset($arrFlags['joins']);
            }

            $this->_sql .= " SET ";
        } else {
            throw new Error("Table name is invalid");
        }

        if (is_array($arrParams) && count($arrParams)) {
            foreach ($arrParams as $f => $p) {
                if ((strpos($f, "`") === false) && (strpos($f, ".") === false) && (strpos($f, "*") === false) && (stripos($f, " as ") === false)) {
                    $f = "`{$f}`";
                }

                if (! is_null($p)) {
                    $this->_sql .= "$f={$this->_escape($p)},";
                } else {
                    $this->_sql .= "$f=NULL,";
                }
            }
        } else {
            throw new Error("No fields to update");
        }

        $this->_sql = substr($this->_sql, 0, - 1);

        if (! is_null($arrWhere) && is_array($arrWhere) && count($arrWhere)) {
            $where_str = " WHERE";
            foreach ($arrWhere as $x => $w) {
                $where_str .= $this->parseClause($w, $x);
            }
            if (strlen($where_str) > strlen(" WHERE")) {
                $this->_sql .= $where_str;
            }
        }

        if (! is_null($arrFlags) && is_array($arrFlags) && count($arrFlags)) {
            $this->_sql .= $this->flags($arrFlags);
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to offer an extended updated functionality by using two different tables.
     *
     * @param string $strTableToUpdate
     *            The table that you want to update (alias 'tbu' is automatically added)
     * @param string $strOriginalTable
     *            The table with the data you want to overwrite to_be_updated table (alias 'o' is automatically added)
     * @param string $strLinkField
     *            The common index value between them that will join the fields
     * @param array|string $arrParams
     *            If string only a single field is updated (tbu.$params = o.$params)
     *            If array each element in the array is a field to be updated (tbu.$param = o.$param)
     *
     * @return mixed
     */
    public function extendedUpdate($strTableToUpdate, $strOriginalTable, $strLinkField, $arrParams)
    {
        $this->_sql = "UPDATE ";
        $this->_queryType = self::EXTENDED_UPDATE;

        if (! is_null($strTableToUpdate) && ! is_null($strOriginalTable) && ! is_null($strLinkField)) {
            $this->_sql .= "$strTableToUpdate tbu INNER JOIN $strOriginalTable o USING ($strLinkField) SET ";
        } else {
            throw new Error("Missing necessary fields");
        }

        if (is_array($arrParams) && count($arrParams)) {
            foreach ($arrParams as $param) {
                if ($param != $strLinkField) {
                    $this->_sql .= "tbu.`$param` = o.`$param`,";
                }
            }
            $this->_sql = substr($this->_sql, 0, - 1);
        } elseif (is_string($arrParams)) {
            $this->_sql .= "tbu.`$arrParams` = o.`$arrParams`";
        } else {
            throw new Exception("Do not understand datatype " . gettype($arrParams), E_ERROR);
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build a replace query
     *
     * @param string $strTableName
     *            The table to update
     * @param array $arrParams
     *            Name/value pair to insert
     *
     * @return NULL|string
     */
    public function replace($strTableName, $arrParams)
    {
        $this->_sql = null;
        $this->_queryType = self::REPLACE;

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql = "REPLACE INTO $strTableName " . "(`" . implode("`,`", array_keys($arrParams)) . "`)";
        } else {
            throw new Error("Table name is invalid");
        }

        $this->_sql .= " VALUES (" . implode(",", array_map([
            $this,
            '_escape'
        ], array_values($arrParams))) . ")";

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build an extended replace statement
     *
     * @param string $strTableName
     *            Table name to update
     * @param array $arrFields
     *            Array of fields
     * @param array $arrParams
     *            Two-dimensional array of values
     *
     * @return NULL|string
     */
    public function extendedReplace($strTableName, $arrFields, $arrParams)
    {
        $this->_sql = null;
        $this->_queryType = self::EXTENDED_REPLACE;

        if (! is_array($arrFields) || ! count($arrFields)) {
            throw new Exception("Error with the field type");
        }

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql = "REPLACE INTO $strTableName " . "(`" . implode("`,`", $arrFields) . "`)";
        } else {
            throw new Error("Table name is invalid");
        }

        if (is_array($arrParams) && count($arrParams)) {
            $this->_sql .= " VALUES ";
            foreach ($arrParams as $p) {
                $this->_sql .= "(" . implode(",", array_map([
                    $this,
                    '_escape'
                ], array_values($p))) . ")";

                if ($p != end($arrParams)) {
                    $this->_sql .= ",";
                }
            }
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build a delete statement
     *
     * @param string $strTableName
     *            Table name to act on
     * @param array $arrFields
     *            [optional]
     *            Optional list of fields to delete (used when including multiple tables)
     * @param array $arrWhere
     *            [optional]
     *            Optional 2-dimensional array to build where clause from
     * @param array $arrJoins
     *            [optional]
     *            Optional 2-dimensional array to add other flags
     *
     * @see Database::where()
     * @see Database::flags()
     *
     * @return string|NULL
     */
    public function delete($strTableName, $arrFields = [], $arrWhere = [], $arrJoins = [])
    {
        $this->_sql = "DELETE";
        $this->_queryType = self::DELETE;

        $this->_logger->debug("Deleting table data");

        if (! is_null($arrFields) && is_array($arrFields) && count($arrFields)) {
            $this->_sql .= " " . implode(",", $arrFields);
        }

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql .= " FROM $strTableName";
        } else {
            throw new Error("Table name is invalid");
        }

        if (! is_null($arrJoins) && is_array($arrJoins) && count($arrJoins)) {
            $this->_sql .= " " . implode(" ", $arrJoins);
        }

        if (! is_null($arrWhere) && is_array($arrWhere) && count($arrWhere)) {
            $where_str = " WHERE";
            foreach ($arrWhere as $x => $w) {
                $where_str .= $this->parseClause($w, $x);
            }
            if (strlen($where_str) > strlen(" WHERE")) {
                $this->_sql .= $where_str;
            }
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build a drop table statement (automatically executes)
     *
     * @param string $strTableName
     *            Table to drop
     * @param string $strType
     *            [optional]
     *            Type of item to drop ('table', 'view') (defaulted to 'table')
     * @param boolean $blnIsTemp
     *            [optional]
     *            Optional boolean if this is a temporary table
     *
     * @return string|NULL
     */
    public function drop($strTableName, $strType = 'table', $blnIsTemp = false)
    {
        $this->_sql = null;
        $this->_queryType = self::DROP;

        switch ($strType) {
            case 'table':
                $strType = 'TABLE';
                break;
            case 'view':
                $strType = 'VIEW';
                break;
            default:
                throw new Error("Invalid type " . gettype($strType), E_ERROR);
        }

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql = "DROP" . ($blnIsTemp ? " TEMPORARY" : "") . " $strType IF EXISTS `{$strTableName}`";
        } else {
            throw new Error("Table name is invalid");
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build a truncate table statement (automatically executes)
     *
     * @param string $strTableName
     *            Table to truncate
     *
     * @throws \Error
     *
     * @return string|NULL
     */
    public function truncate($strTableName)
    {
        $this->_sql = null;
        $this->_queryType = self::TRUNCATE;

        if (! is_null($strTableName) && is_string($strTableName)) {
            $this->_sql = "TRUNCATE TABLE $strTableName";
        } else {
            throw new Error("Table name is invalid");
        }

        if (self::$autorun) {
            return $this->execute(MYSQLI_BOTH);
        }

        return $this->_sql;
    }

    /**
     * Function to build a create temporary table statement
     *
     * @param string $strTableName
     *            Name to give the table when creating
     * @param boolean $blnIsTemp
     *            [optional]
     *            Optional boolean to make the table a temporary table
     * @param mixed $strSelect
     *            [optional]
     *            Optional parameter if null uses last built statement
     *            If string, will be made the SQL statement executed to create the table
     *            If array, 2-dimensional array with "field", "datatype" values to build table fields
     *
     * @return NULL|string
     */
    public function createTable($strTableName, $blnIsTemp = false, $strSelect = null)
    {
        $this->_queryType = self::CREATE_TABLE;

        if (is_null($strSelect) && ! is_null($this->_sql) && substr($this->_sql, 0, 6) == 'SELECT') {
            $this->_sql = "CREATE" . ($blnIsTemp ? " TEMPORARY" : "") . " TABLE IF NOT EXISTS $strTableName AS ($this->_sql)";
        } elseif (! is_null($strTableName) && is_string($strTableName) && is_string($strSelect)) {
            $this->_sql = "CREATE" . ($blnIsTemp ? " TEMPORARY" : "") . " TABLE IF NOT EXISTS $strTableName AS ($strSelect)";
        } elseif (! is_null($strTableName) && is_string($strTableName) && is_array($strSelect)) {
            $this->_sql = "CREATE" . ($blnIsTemp ? " TEMPORARY" : "") . " TABLE IF NOT EXISTS $strTableName (";

            foreach ($strSelect as $field) {
                $default = null;
                if (isset($field['default'])) {
                    $default = (is_null($field['default']) ? "" : " DEFAULT '{$field['default']}'");
                }
                $this->_sql .= "`{$field['field']}` {$field['datatype']}" . $default . (isset($field['option']) ? " {$field['option']}" : '') . ",";
            }
            $this->_sql = substr($this->_sql, 0, - 1) . ")";
        }

        if (self::$autorun) {
            return $this->execute();
        }

        return $this->_sql;
    }

    /**
     * Function to create a table using a stdClass object derived from JSON
     *
     * @param \stdClass $json
     *
     * @example /examples/create_table_json.json
     *
     */
    public function createTableJson($json)
    {
        $this->_queryType = self::CREATE_TABLE;
        $this->_c->select_db($json->schema);

        $this->_sql = "CREATE TABLE IF NOT EXISTS `{$json->name}` (";
        foreach ($json->fields as $field) {
            $this->_sql .= "`{$field->name}` {$field->dataType}";

            if ($field->dataType == 'enum') {
                $this->_sql .= "('" . implode("','", $field->values) . "')";
            }

            if ($field->ai) {
                $this->_sql .= " AUTO_INCREMENT";
            }

            if ($field->nn) {
                $this->_sql .= " NOT NULL";
            } else {
                if ($field->default === null) {
                    $this->_sql .= " DEFAULT NULL";
                } elseif (strlen($field->default)) {
                    $this->_sql .= " DEFAULT '{$field->default}'";
                }
            }

            if ($field != end($json->fields)) {
                $this->_sql .= ",";
            }
        }

        if (isset($json->index) && count($json->index)) {
            foreach ($json->index as $ind) {
                $this->_sql .= ", " . strtoupper($ind->type) . " `{$ind->id}` (`{$ind->ref}`)";
            }
        }

        if (isset($json->constraints) && count($json->constraints)) {
            foreach ($json->constraints as $con) {
                $this->_sql .= ", CONSTRAINT `{$con->id}` " . "FOREIGN KEY (`{$con->local}`) " . "REFERENCES `{$con->schema}`.`{$con->table}` (`{$con->field}`) " . "ON DELETE " . (is_null($con->delete) ? "NO ACTION" : strtoupper($con->delete)) . " " . "ON UPDATE " . (is_null($con->update) ? "NO ACTION" : strtoupper($con->update));
            }
        }

        if (isset($json->unique) && count($json->unique)) {
            $this->_sql .= ", UNIQUE(`" . implode("`,`", $json->unique) . "`)";
        }

        if (isset($json->primary_key) && count($json->primary_key)) {
            $this->_sql .= ", PRIMARY KEY(`" . implode("`,`", $json->primary_key) . "`))";
        } else {
            if (substr($this->_sql, - 1) == ',') {
                $this->_sql = substr($this->_sql, 0, - 1);
            }

            $this->_sql .= ")";
        }

        $this->execute(MYSQLI_BOTH);
    }

    /**
     * Function to alter a existing table
     *
     * @param string $strTableName
     *            Table to alter
     * @param int $intAction
     *            What action should be taken ('add-column', 'drop-column', 'modify-column')
     * @param mixed $arrParams
     *            For add column this is a stdClass object that has the same elements as the example json
     *
     * @return mixed
     */
    public function alterTable($strTableName, $intAction, $arrParams)
    {
        $this->_queryType = self::ALTER_TABLE;
        $this->_sql = "ALTER TABLE $strTableName";
        if ($intAction == self::ADD_COLUMN) {
            $nn = ($arrParams->nn ? " NOT NULL" : "");
            $default = null;
            if ($arrParams->default === null) {
                $default = " DEFAULT NULL";
            } elseif (strlen($arrParams->default)) {
                $default = " DEFAULT {$this->_escape($arrParams->default)}";
            }
            $this->_sql .= " ADD COLUMN `{$arrParams->name}` {$arrParams->dataType}" . $nn . $default;
        } elseif ($intAction == self::DROP_COLUMN) {
            $this->_sql .= " DROP COLUMN ";
            foreach ($arrParams as $col) {
                $this->_sql .= "`{$col->name}`";

                if ($col != end($arrParams)) {
                    $this->_sql .= ",";
                }
            }
        } elseif ($intAction == self::MODIFY_COLUMN) {
            $this->_sql .= " MODIFY COLUMN";
            $nn = ($arrParams->nn ? " NOT NULL" : "");
            $default = null;
            if ($arrParams->default === null) {
                $default = " DEFAULT NULL";
            } elseif (strlen($arrParams->default)) {
                $default = " DEFAULT {$this->_escape($arrParams->default)}";
            }
            $this->_sql .= " `{$arrParams->name}` `{$arrParams->new_name}` {$arrParams->dataType}" . $nn . $default;
        }

        if (self::$autorun) {
            return $this->execute();
        }

        return $this->_sql;
    }

    /**
     * Check to see if a field in a table exists
     *
     * @param string $strTableName
     *            Table to check
     * @param string $strFieldName
     *            Field name to find
     *
     * @return boolean Returns TRUE if field is found in that schema and table, otherwise FALSE
     */
    public function fieldExists($strTableName, $strFieldName)
    {
        $fdata = $this->fieldData($strTableName);

        if (is_array($fdata) && count($fdata)) {
            foreach ($fdata as $field) {
                if ($field->name == $strFieldName) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Function to get the column data (datatype, flags, defaults, etc)
     *
     * @param string $strTableName
     *            Table to query
     * @param mixed $field
     *            [optional]
     *            Optional field to retrieve data (if null, returns data from all fields)
     *
     * @return array
     */
    public function fieldData($strTableName, $field = null)
    {
        if (is_null($field)) {
            $res = $this->_c->query("SELECT * FROM $strTableName LIMIT 1");
        } elseif (is_array($field)) {
            $res = $this->_c->query("SELECT `" . implode("`,`", $field) . "` FROM $strTableName LIMIT 1");
        } elseif (is_string($field)) {
            $res = $this->_c->query("SELECT $field FROM $strTableName LIMIT 1");
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
     * @param array $pks
     * @param object $index
     *
     * @return array|string
     */
    public function fieldCheck($field_data, $check, $pks, $index)
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
            $this->_logger->notice("Wrong datatype", [
                'name' => $field_data->name,
                'datatype' => $check->dataType
            ]);
            $ret = " CHANGE COLUMN `{$field_data->name}` `{$check->name}` {$check->dataType}" . "{$nn}{$default}";
        } elseif (! is_null($check->length) && $field_data->length != $check->length) {
            $this->_logger->notice("Incorrect size", [
                'name' => $field_data->name,
                'current' => $field_data->length,
                'new_size' => $check->length
            ]);
            $ret = " CHANGE COLUMN `{$field_data->name}` `{$check->name}` {$check->dataType}" . "{$nn}{$default}";
        } elseif ($check->type == MYSQLI_TYPE_ENUM && ! ($field_data->flags & MYSQLI_ENUM_FLAG)) {
            $this->_logger->notice("Setting ENUM type", [
                'name' => $field_data->name,
                'values' => implode(",", $check->values)
            ]);
            $ret = " CHANGE COLUMN `{$field_data->name}` `{$check->name}` {$check->dataType}('" . implode("','", $check->values) . "')" . "{$nn}{$default}";
        }

        if (! is_null($index) && count($index)) {
            foreach ($index as $ind) {
                if ($check->name == $ind->ref && ! ($field_data->flags & MYSQLI_MULTIPLE_KEY_FLAG)) {
                    $this->_logger->debug("Missing index", [
                        'name' => $field_data->name
                    ]);
                    $ret .= ($ret ? "," : "") . " ADD INDEX `{$ind->id}` (`{$ind->ref}` ASC)";
                }
            }
        }

        if (in_array($check->name, $pks) && ! ($field_data->flags & MYSQLI_PRI_KEY_FLAG)) {
            $this->_logger->debug("Setting PKs", [
                'keys' => implode(',', $pks)
            ]);
            $ret .= ($ret ? "," : "") . " DROP PRIMARY KEY, ADD PRIMARY KEY(`" . implode("`,`", $pks) . "`)";
        }

        return $ret;
    }

    /**
     * Function to check for the existence of a table within a schema
     *
     * @param string $strSchema
     *            The schema to search in
     * @param string $strTableName
     *            Table to search for
     *
     * @return integer|boolean Returns number of tables that match if table is found in that schema, otherwise FALSE
     */
    public function tableExists($strSchema, $strTableName)
    {
        if (! $this->_c->select_db($strSchema)) {
            fwrite("php://stdout", $this->_c->error . PHP_EOL);
        }
        $sql = "SHOW TABLES LIKE '{$strTableName}'";

        if ($res = $this->_c->query($sql)) {
            if (gettype($res) == 'object' && is_a($res, 'mysqli_result') && $res->num_rows) {
                return $res->num_rows;
            }
        } else {
            if ($this->_c->errno) {
                fwrite("php://stdout", $this->_c->error . PHP_EOL);
            }
        }

        return false;
    }

    /**
     * Function to detect if string is a JSON object or not
     *
     * @param string $strVal
     *
     * @return boolean
     */
    public function isJson($strVal)
    {
        json_decode($strVal);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    /**
     * Function to escape SQL characters to prevent SQL injection
     *
     * @param mixed $val
     *            Value to escape
     * @param boolean $blnEscape
     *            Decide if we should escape or not
     *
     * @return string Escaped value
     */
    public function _escape($val, $blnEscape = true)
    {
        if (is_null($val) || (is_string($val) && strtolower($val) == 'null')) {
            return 'NULL';
        } elseif (is_numeric($val) || is_string($val)) {
            if (stripos($val, "IF(") !== false) {
                return $val;
            }
            elseif ($blnEscape) {
                return "'{$this->_c->real_escape_string($val)}'";
            }
            return $val;
        } elseif (is_a($val, 'DateTime')) {
            return "'{$val->format(MYSQL_DATETIME)}'";
        } elseif (is_bool($val)) {
            return $val ? "'1'" : "'0'";
        } elseif (gettype($val) == 'object' && method_exists($val, '_escape')) {
            $ret = call_user_func([
                $val,
                '_escape'
            ]);
            if ($ret !== false) {
                return $ret;
            } else {
                throw new Exception("Error in return from _escape method in " . get_class($val), E_ERROR);
            }
        } elseif (gettype($val) == 'object') {
            $this->_logger->error("Unknown object to escape " . get_class($val) . " in SQL string {$this->_sql}");
            return;
        }

        throw new Exception("Unknown datatype to escape in SQL string {$this->_sql} " . gettype($val), E_ERROR);
    }

    /**
     * Function to retrieve all results
     *
     * @param int $intResultType
     *
     * @return mixed
     */
    public function fetchAll($intResultType = MYSQLI_ASSOC)
    {
        $res = [];
        if (method_exists('mysqli_result', 'fetch_all')) { // Compatibility layer with PHP < 5.3
            $res = $this->_result->fetch_all($intResultType);
        } else {
            while ($tmp = $this->_result->fetch_array($intResultType)) {
                $res[] = $tmp;
            }
        }

        return $res;
    }

    /**
     * Function to populate the fields for the SQL
     *
     * @param array|string $fields
     *            [optional]
     *            Optional array of fields to string together to create a field list
     *
     * @return string
     */
    public function fields($fields = null)
    {
        $ret = null;

        if (is_array($fields) && count($fields) && isset($fields[0]) && is_string($fields[0])) {
            foreach ($fields as $field) {
                if ((strpos($field, '`') === false) && (strpos($field, '.') === false) && (strpos($field, '*') === false) && (strpos($field, 'JSON_') === false) && (stripos($field, ' as ') === false)) {
                    $ret .= "`$field`,";
                } else {
                    $ret .= "$field,";
                }
            }
            $ret = substr($ret, - 1) == ',' ? substr($ret, 0, - 1) : $ret;
        } elseif (is_string($fields)) {
            $ret = $fields;
        } elseif (is_null($fields)) {
            $ret = "*";
        } else {
            throw new \InvalidArgumentException("Invalid field type");
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
     *            [
     *            &nbsp;&nbsp;'joins' => [
     *            &nbsp;&nbsp;&nbsp;&nbsp;"JOIN table2 t2 ON t2.id=t1.id"
     *            &nbsp;&nbsp;],
     *            &nbsp;&nbsp;'group' => 'field',
     *            &nbsp;&nbsp;'having' => 'field',
     *            &nbsp;&nbsp;'order' => 'field',
     *            &nbsp;&nbsp;'start' => 0,
     *            &nbsp;&nbsp;'limit' => 0
     *            ]
     *            </code>
     *
     * @see Database::groups()
     * @see Database::having()
     * @see Database::order()
     *
     * @return string
     */
    public function flags($arrFlags)
    {
        $ret = '';

        if (isset($arrFlags['group'])) {
            $ret .= $this->groups($arrFlags['group']);
        }

        if (isset($arrFlags['having']) && is_array($arrFlags['having'])) {
            $having = " HAVING";
            foreach ($arrFlags['having'] as $x => $h) {
                $having .= $this->parseClause($h, $x);
            }
            if (strlen($having) > strlen(" HAVING")) {
                $ret .= $having;
            }
        }

        if (isset($arrFlags['order'])) {
            $ret .= $this->order($arrFlags['order']);
        }

        if (isset($arrFlags['limit']) && (is_string($arrFlags['limit']) || is_numeric($arrFlags['limit']))) {
            $ret .= " LIMIT ";
            if (isset($arrFlags['start']) && (is_string($arrFlags['start']) || is_numeric($arrFlags['start']))) {
                $ret .= "{$arrFlags['start']},";
            }
            $ret .= "{$arrFlags['limit']}";
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
    public function groups($groups)
    {
        $ret = '';
        if (is_array($groups) && count($groups)) {
            $ret .= " GROUP BY";

            foreach ($groups as $grp) {
                $ret .= " $grp";

                if ($grp != end($groups)) {
                    $ret .= ",";
                }
            }
        } elseif (is_string($groups)) {
            $ret .= " GROUP BY {$groups}";
        } else {
            throw (new Exception("Error in datatype for groups " . gettype($groups), E_ERROR));
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
    public function order($order)
    {
        $ret = '';
        if (is_array($order)) {
            $ret .= " ORDER BY";

            foreach ($order as $ord) {
                $ret .= " {$ord['field']} {$ord['sort']}";

                if ($ord != end($order)) {
                    $ret .= ",";
                }
            }
        } elseif (is_string($order)) {
            $ret .= " ORDER BY {$order}";
        }

        return $ret;
    }

    /**
     * Function to see if a constraint exists
     *
     * @param string $strConstraintId
     *
     * @return boolean
     */
    public function isConstraint($strConstraintId)
    {
        $res = $this->_c->query("SELECT * FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_NAME = '{$strConstraintId}'");

        if ($res->num_rows) {
            return true;
        }

        return false;
    }

    /**
     * Function to parse where and having clauses
     *
     * @param array $arrClause
     * @param int $intIndex
     */
    public function parseClause($arrClause, $intIndex)
    {
        $ret = null;

        $this->_logger->debug("Parsing clause", $arrClause);

        if (! isset($arrClause['field']) && isset($arrClause['close-paren']) && $arrClause['close-paren']) {
            $ret .= ")";
            return $ret;
        } elseif ($intIndex > 0 && ! isset($arrClause['sql_op'])) {
            $this->_logger->warning("Missing sql_op field to identify how current and previous WHERE clause statements should be linked ('AND', 'OR', 'XOR', etc), skipped", [
                'clause' => implode(",", $arrClause)
            ]);
            return;
        }

        $op = '=';
        if (isset($arrClause['op'])) {
            $op = $arrClause['op'];
        }

        switch ($op) {
            case self::BETWEEN:
                if (! isset($arrClause['field']) || ! isset($arrClause['low']) || ! isset($arrClause['high'])) {
                    $this->_logger->warning("Missing field, low, or high for BETWEEN where clause, skipping");
                    return;
                }
                break;
            default:
                if (! isset($arrClause['field']) || ! isset($arrClause['value'])) {
                    $this->_logger->warning("Missing field or value for WHERE clause, skipping", $arrClause);
                    return;
                }
        }

        if ($intIndex > 0) {
            $ret .= " {$arrClause['sql_op']}";
        }

        if (isset($arrClause['open-paren']) && $arrClause['open-paren']) {
            $ret .= " (";
        }

        if (isset($arrClause['backticks']) && ! $arrClause['backticks']) {
            $field = $arrClause['field'];
        } else {
            $field = "`{$arrClause['field']}`";
        }

        if ($op == self::IN || $op == self::NOT_IN) {
            if (is_string($arrClause['value'])) {
                $ret .= " {$field} {$op} " . (strpos($arrClause['value'], '(') !== false ? $arrClause['value'] : "({$arrClause['value']})");
            } elseif (is_array($arrClause['value'])) {
                $ret .= " {$field} {$op} (" . implode(",", array_map([
                    $this,
                    '_escape'
                ], $arrClause['value'])) . ")";
            } else {
                $this->_logger->error("Invalid datatype for IN WHERE clause, only string and array allowed " . gettype($arrClause['value']), $arrClause);
                throw new Exception("Invalid datatype for IN WHERE clause", E_ERROR);
            }
        } elseif ($op == self::BETWEEN) {
            $ret .= " {$field} BETWEEN {$this->_escape($arrClause['low'])} AND {$this->_escape($arrClause['high'])}";
        } else {
            if (isset($arrClause['escape']) && ! $arrClause['escape']) {
                $value = $arrClause['value'];
            } else {
                $value = $this->_escape($arrClause['value']);
            }

            if (isset($arrClause['case_insensitive']) && $arrClause['case_insensitive']) {
                $ret .= " LOWER({$field}) {$op} LOWER({$this->_escape($arrClause['value'])})";
            } elseif (preg_match("/\(SELECT/", $arrClause['value'])) {
                $ret .= " {$field} {$op} {$arrClause['value']}";
            } else {
                $ret .= " {$field} {$op} {$value}";
            }
        }

        if (isset($arrClause['close-paren']) && $arrClause['close-paren']) {
            $ret .= ")";
        }

        return $ret;
    }
}
