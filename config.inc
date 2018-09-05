<?php

/**
 * File: config.inc
 * Author: Ryan Prather <ryan.prather@cyberperspectives.com>
 * Purpose: File to store config information for Sagacity
 * Created: Nov 14, 2017
 *
 * Copyright 2017-2018: Cyber Perspective, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Nov 14, 2017 - File created
 *  - May 24, 2018 - Updated constants for 1.3.2 release
 *  - Jun 2, 2018 - Added new STIG_EXCLUSIONS constant to permanently exclude STIGs
 *  - Aug 28, 2018 - Updated constants for 1.3.3 release
 */
// @new
/**
 * Constant defining a debug log level
 *
 * @var int
 */
define('E_DEBUG', 65535);
/**
 * System paths
 */
define('DOC_ROOT', '{DOC_ROOT}');
define('PWD_FILE', '{PWD_FILE}');
define('TMP', '{TMP_PATH}');
define('VER', '1.3.3');
define('REL_DATE', '2018-08-31');
define('LOG_LEVEL', '{E_ERROR}');
define('LOG_PATH', '{LOG_PATH}');
define('SALT', '{SALT}');
define('ALGORITHM', '{ALGORITHM}');

/**
 * 3rd party tool paths
 */
define('PHP_BIN', '{PHP_BIN}');
define('PHP_CONF', '{PHP_CONF}');
define('NMAP_PATH', '{NMAP_PATH}');
define('NESSUS_SVR', '{NESSUS_SVR}');

/**
 * Database config
 */
define('DB_SERVER', '{DB_SERVER}');
define('DB_BIN', '{DB_BIN}');

/**
 * Application constants
 */
define('FLATTEN', '{FLATTEN}');
define('WRAP_TEXT', '{WRAP_TEXT}');
define('NOTIFICATIONS', '{NOTIFICATIONS}');
define('PORT_LIMIT', '{PORT_LIMIT}');
define('MAX_RESULTS', '{MAX_RESULTS}');
define('ECHECKLIST_FORMAT', '{ECHECKLIST_FORMAT}');
define('UPDATE_FREQ', '{UPDATE_FREQ}');

/**
 * Company variables
 */
define('COMPANY', '{COMPANY}');
define('COMP_ADD', '{COMP_ADD}');
define('LAST_MODIFIED_BY', '{LAST_MODIFIED_BY}');
define('CREATOR', '{CREATOR}');
define('SYSTEM_CLASS', '{SYSTEM_CLASS}');
define('CLASSIFIED_BY', '{CLASSIFIED_BY}');
define('SCG', '{SCG}');
define('DERIVED_ON', '{DERIVED_ON}');
define('DECLASSIFY_ON', '{DECLASSIFY_ON}');

/**
 * Constant to be used to permanently exclude STIGs
 */
define('STIG_EXCLUSIONS', '');

/**
 * Constant to define MySQL's DateTime format
 *
 * @var string
 */
define('MYSQL_DT_FORMAT', "Y-m-d H:i:s");

/**
 * Constant to define MySQL's Date format
 *
 * @var string
 */
define('MYSQL_D_FORMAT', "Y-m-d");

/**
 * Constant to define JSON header return
 *
 * @var string
 */
define('JSON', 'application/json');

// {{{ UNSUPPORTED
/**
 * Constant that is default for file detection
 *
 * @var string
 */
define('UNSUPPORTED', 'UNSUPPORTED');
// }}}
// {{{ XML
/**
 * Constant for SCC XCCDF files
 *
 * @var string
 */
define('SCC_XCCDF', 'SCC_XCCDF');

/**
 * Constant for SCC OVAL files
 *
 * @var string
 */
define('SCC_OVAL', 'SCC_OVAL');

/**
 * Constant for DISA STIG XML files
 *
 * @var string
 */
define('DISA_STIG_XML', 'DISA_STIG_XML');

/**
 * Constant for DISA STIG OVAL XML files
 *
 * @var string
 */
define('DISA_STIG_OVAL', 'DISA_STIG_OVAL');

/**
 * Constant for Golddisk result files
 *
 * @var string
 */
define('GOLDDISK', 'GOLDDISK');

/**
 * Constant for NMap XML files
 *
 * @var string
 */
define('NMAP_XML', 'NMAP_XML');

/**
 * Constant for MBSA XML result files
 *
 * @var string
 */
define('MBSA_XML', 'MBSA_XML');

/**
 * Constant for MSSQL XML result files from script
 *
 * @var string
 */
define('MSSQL_XML', 'MSSQL_XML');

/**
 * Constant for unsupported XML files
 *
 * @var string
 */
define('UNSUPPORTED_XML', 'UNSUPPORTED_XML');
// }}}
// {{{ NESSUS
/**
 * Constant for NESSUS result files
 *
 * @var string
 */
define('NESSUS', 'NESSUS');

/**
 * Constant for Nessus messages log file
 *
 * @var string
 */
define('NESSUS_MESSAGES', 'NESSUS_MESSAGES');

/**
 * Constant for GZipped Nessus plugin file
 *
 * @var string
 */
define('NESSUS_PLUGIN_GZIP', 'NESSUS_PLUGIN_GZIP');

/**
 * Constant for Nessus plugin .nasl file
 *
 * @var string
 */
define('NESSUS_PLUGIN_NASL', 'NESSUS_PLUGIN_NASL');

/**
 * Constant for unsupported Nessus binary files
 *
 * @var string
 */
define('UNSUPPORTED_NESSUS_NBE', 'UNSUPPORTED_NESSUS_NBE');
// }}}
// {{{ .txt
/**
 * Constant for unsupported SCC text result files
 *
 * @var string
 */
define('UNSUPPORTED_SCC_TEXT', 'UNSUPPORTED_SCC_TEXT');

/**
 * Constant for unsupported SCC error log file
 *
 * @var string
 */
define('UNSUPPORTED_SCC_ERROR', 'UNSUPPORTED_SCC_ERROR');

/**
 * Constant for NMap text result files
 *
 * @var string
 */
define('NMAP_TEXT', 'NMAP_TEXT');

/**
 * Constant for NMap greppable text files
 *
 * @var string
 */
define('NMAP_GREPABLE', 'NMAP_GREPABLE');

/**
 * Constant for NMap Network Device result file
 *
 * @var string
 */
define('NMAP_NETWORK_DEVICE', 'NMAP_NETWORK_DEVICE');

/**
 * Constant for MBSA result text file
 *
 * @var string
 */
define('MBSA_TEXT', 'MBSA_TEXT');

/**
 * Constant for any other unsupported text file
 *
 * @var string
 */
define('UNSUPPORTED_TEXT', 'UNSUPPORTED TEXT');

/**
 * Constant for data files from host collection scripts
 *
 * @var string
 */
define('HOST_DATA_COLLECTION', 'HOST_DATA_COLLECTION');
// }}}
// {{{ .csv
/**
 * Constant for PDI catalog (not really used)
 *
 * @var string
 */
define('PDI_CATALOG', 'PDI_CATALOG');

/**
 * Constant for CSV echecklist file
 *
 * @var string
 */
define('ECHECKLIST_CSV', 'ECHECKLIST_CSV');

/**
 * Constant for unsupported retina CSV file format
 *
 * @var string
 */
define('UNSUPPORTED_RETINA_CSV', 'UNSUPPORTED_RETINA_CSV');

/**
 * Constant for any other unsupported CSV file format
 *
 * @var string
 */
define('UNSUPPORTED_CSV', 'UNSUPPORTED_CSV');
// }}}
// {{{ .xlsx|.xls
/**
 * Constant for an Excel technical echecklist file
 *
 * @var string
 */
define('TECH_ECHECKLIST_EXCEL', 'TECH_ECHECKLIST_EXCEL');

/**
 * Constant for an Excel procedural echecklist file
 *
 * @var string
 */
define('PROC_ECHECKLIST_EXCEL', 'PROC_ECHECKLIST_EXCEL');

/**
 * Constant for any other unsupported Excel file
 *
 * @var string
 */
define('UNSUPPORTED_EXCEL', 'UNSUPPORTED_EXCEL');
// }}}
// {{{ .zip
/**
 * Constant for DISA STIG benchmark ZIP file
 *
 * @var string
 */
define('DISA_STIG_BENCHMARK_ZIP', 'DISA_STIG_BENCHMARK');

/**
 * Constant for DISA STIG compilation library zip file
 *
 * @var string
 */
define('DISA_STIG_LIBRARY_ZIP', 'DISA_STIG_LIBRARY_ZIP');
// }}}
// {{{ .ckl
/**
 * Constant for STIG Viewer CKL extension file
 *
 * @var string
 */
define('STIG_VIEWER_CKL', 'STIG_VIEWER_CKL');
// }}}
// {{{ .Result|.log|.Examples
/**
 * Constant for unsupported UNIX SRR result file
 *
 * @var string
 */
define('UNSUPPORTED_UNIX_SRR', 'UNSUPPORTED_UNIX_SRR');
// }}}

/**
 * Constant to designate file is a directory
 *
 * @var string
 */
define('DIRECTORY', 'DIRECTORY');

/**
 * Constant to designate an unsupported ini file (desktop.ini)
 *
 * @var string
 */
define('UNSUPPORTED_INI', 'UNSUPPORTED_INI');

