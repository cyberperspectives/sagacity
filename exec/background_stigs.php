<?php
/**
 * File: background_stigs.php
 * Author: Ryan Prather
 * Purpose: To allow scripts to run in the background
 *  Currently only implements the STIG XML importing
 * Created: Jul 18, 2014
 *
 * Portions Copyright (c) 2016-2017: Cyber Perspectives, LLC All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jul 18, 2014 - File created
 *  - Dec 7, 2016 - Changed PHP constant to PHP_BIN and added Cyber Perspectives copyright
 *  - Dec 12, 2016 - Revised text for to run parse_stig script, delete files only if --delete parameter is set
 *  - Feb 15, 2017 - Formatting, revised the printed messages throughout the script, and converted file_types constants where required
 *  - Feb 21, 2017 - Fixed paths and revised progress output, Revised directories and fixed output
 *  - Mar 3, 2017 - Now shuffling the STIG files to prevent duplicate STIG creation and fixed bug with scripts not being updated to complete when done
 *  - Mar 8, 2017 - Fixed typo with catalog_scripts table and added update to $count value when waiting for all script to complete
 *  - Apr 5, 2017 - Hard coded parsing 20 STIGs instead of using MAX_RESULTS constant
 *  - Jun 27, 2017 - Cleanup
 *  - Jul 13, 2017 - Changed STIG parsing to serial instead of parallel to fix issue with duplicate STIGs from race conditions
 *  - May 31, 2018 - Added deletion when files match exclusion
 *  - Jun 2, 2018 - Added code to check STIG_EXCLUSIONS constant to for permanently excluded STIGs
 */
$cmd = getopt("x::h::d::", ["debug::", "delete::", "ia::", "extract::", "help::", 'exclude::']);

if (isset($cmd['help']) || isset($cmd['h'])) {
    die(usage());
}

set_time_limit(0);

require_once 'config.inc';
require_once 'helper.inc';
require_once 'database.inc';
require_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

$log_level = Logger::ERROR;
switch (LOG_LEVEL) {
    case E_WARNING:
        $log_level = Logger::WARNING;
        break;
    case E_NOTICE:
        $log_level = Logger::NOTICE;
        break;
    case E_DEBUG:
        $log_level = Logger::DEBUG;
}

if (isset($cmd['debug'])) {
    $log_level = Logger::DEBUG;
}

$stream = new StreamHandler("php://output", $log_level);
$stream->setFormatter(new LineFormatter("%datetime% %level_name% %message%" . PHP_EOL, "H:i:s.u"));

$log = new Logger("stig_parser");
$log->pushHandler(new StreamHandler(LOG_PATH . "/stig_parser.log", $log_level));
$log->pushHandler($stream);

check_path(TMP . "/stigs");
check_path(TMP . "/stigs/zip");
check_path(TMP . "/stigs/checklist");
check_path(TMP . "/stigs/xml");
check_path(DOC_ROOT . "/reference/stigs");

$path = realpath(TMP . "/stigs");
if (isset($cmd['d']) && $cmd['d']) {
    $path = $cmd['d'];
}

chdir($path);

$db        = new db();
$stack     = [];
$zip_files = glob("*.zip");
$zip       = new ZipArchive();

// Find the .zip files that were uploaded
foreach ($zip_files as $file) {
    $ft = FileDetection($file);
    if ($ft['type'] == DISA_STIG_LIBRARY_ZIP) {
        $log->info("Extracting $file");
        $zip->open($file);
        $zip->extractTo(realpath(TMP . "/stigs/checklist"));
        $zip->close();
        if (isset($cmd['delete'])) {
            unlink($file);
        }
    }
}

// traverse the checklist directory to find all the zip files and extract those
for ($x = 0; $x < 2; $x++) {
    $dir   = new RecursiveDirectoryIterator(realpath(TMP . "/stigs/checklist"));
    $files = new RecursiveIteratorIterator($dir);
    directory_crawl($files);
}

// traverse the zip directory, and extract the xml, xsl, jpg, or gif files.
for ($x = 0; $x < 3; $x++) {
    $dir   = new RecursiveDirectoryIterator(realpath(TMP . "/stigs/zip"));
    $files = new RecursiveIteratorIterator($dir);
    directory_crawl($files);
}

if (isset($cmd['x']) || isset($cmd['extract'])) {
    $log->info("Extract only complete");
    die;
}

// find all the xml files in the directory
chdir(TMP . "/stigs/xml");
$xml_files = glob("*.xml");

// change back to the document root directory
chdir(DOC_ROOT);
$count = 0;
$db->help->update("settings", ['meta_value' => 0], [
    [
        'field' => 'meta_key',
        'value' => 'stig-progress'
    ]
]);
$db->help->execute();

$regex   = null;
if (isset($cmd['exclude'])) {
    $regex = $cmd['exclude'];
}

foreach ($xml_files as $key => $file) {
    // if the file has a space in the file name we need to replace it because it will cause parsing errors
    if (strpos($file, ' ') !== false) {
        $new_file        = str_replace(' ', '_', $file);
        rename(realpath(TMP . "/stigs/xml/$file"), TMP . "/stigs/xml/$new_file");
        $xml_files[$key] = $file            = $new_file;
        copy(realpath(TMP . "/stigs/xml/$file"), realpath(DOC_ROOT . "/reference/stigs") . "/$file");
    }

    if (!is_null($regex) && preg_match("/$regex/i", $file)) {
        unlink($file);
        $log->debug("Skipping $file due to matching regex");
        continue;
    }
    elseif(!empty(STIG_EXCLUSIONS) && preg_match("/" . STIG_EXCLUSIONS . "/i", $file)) {
        unlink($file);
        $log->debug("Skipping $file due to matching STIG exclusion");
        continue;
    }

    // determine the file type
    $ft = FileDetection(TMP . "/stigs/xml/$file");

    // add the file to the stack if it is of the proper type
    //    can add additional types as the parser are created
    if ($ft['type'] == DISA_STIG_XML) {
        $log->info("Parsing STIG file: $file");

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/parse_stig.php") . " --" .
            " -f=\"" . realpath(TMP . "/stigs/xml/{$file}") . "\"" .
            (isset($cmd['debug']) ? " --debug" : "");

        $db->add_Catalog_Script(basename($file));
        passthru($script);
    }
    else {
        $log->debug("Skipping $file");
        continue;
    }

    $count++;

    $db->help->update("settings", ['meta_value' => number_format(($count / count($xml_files) * 100), 2)], [
        [
            'field' => 'meta_key',
            'op'    => '=',
            'value' => 'stig-progress'
        ]
    ]);
    $db->help->execute();
}

$db->help->update("catalog_scripts", ['status' => 'COMPLETE'], [
    [
        'field' => 'perc_comp',
        'op'    => '=',
        'value' => 100
    ],
    [
        'field'  => 'status',
        'op'     => '=',
        'value'  => 'RUNNING',
        'sql_op' => 'AND'
    ]
]);
$db->help->execute();
$db->help->update("settings", ['meta_value' => 100], [
    [
        'field' => 'meta_key',
        'op'    => IN,
        'value' => ['stig-dl-progress', 'stig-progress']
    ]
]);
$db->help->execute();

if (isset($cmd['delete'])) {
    if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
        exec("del /S /Q /F " . realpath(TMP . "/stigs/checklist") . "\\*");
        exec("del /S /Q /F " . realpath(TMP . "/stigs/zip") . "\\*");
    }
    else {
        exec("rm -rf " . realpath(TMP . "/stigs/checklist") . "/*");
        exec("rm -rf " . realpath(TMP . "/stigs/zip") . "/*");
    }
}

/**
 * Function to crawl directory structure to find zip, xml, xsl, gif, and jpg files
 *
 * @param RecursiveIteratorIterator $files
 */
function directory_crawl($files)
{
    global $zip;

    foreach ($files as $file) {
        if (preg_match('/\.zip/', $file)) {
            if ($zip->open($file) === true) {
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $contents = '';
                    $in_Skips = false;
                    $path     = '';
                    $filename = str_replace('\\', '/', $zip->getNameIndex($i));
                    $fileinfo = pathinfo($filename);

                    if (isset($fileinfo['extension']) && !$in_Skips) {
                        switch (strtolower($fileinfo['extension'])) {
                            case 'zip':
                                $path = TMP . "/stigs/zip/";
                                break;
                            case 'xml':
                                if (!preg_match('/xccdf/i', $fileinfo['basename'])) {
                                    continue;
                                }
                                elseif (strpos($fileinfo['basename'], "$") !== false) {
                                    continue;
                                }

                                $path = TMP . "/stigs/xml/";
                                break;
                            case 'xsl':
                            case 'gif':
                            case 'jpg':
                                $path = DOC_ROOT . "/reference/stigs/";
                                break;
                        }

                        if ($path) {
                            $fp = $zip->getStream($filename);
                            if (!$fp) {
                                error_log("Couldn't get zip file stream for file $filename in $file");
                            }
                            else {
                                while (!feof($fp)) {
                                    $contents .= fread($fp, 1024);
                                }

                                fclose($fp);
                                if (file_put_contents($path . $fileinfo['basename'], $contents) === false) {
                                    die;
                                }
                            }
                        }
                    }
                }
                $zip->close();
            }
        }
    }
}

function usage()
{
    print <<<EOO
Purpose: This program was written to look at all files in the {doc_root}/tmp directory, determine what parser is needed, then call that parser with the appropriate flags.

Usage: background_stigs.php [-x|--extract] [-d="directory"] [--debug] [--regex="ex1|ex2"] [--delete] [--ia] [-h|--help]

 -x|--extract       Simply extract the contents of a .zip file (STIG library) to it's proper places, do not parse the contents
 -d="directory"     Directory to search for the zip and xml files in (optional, defaults to {doc_root}/tmp)

 --regex="ex1|ex2"  Insert a valid regex expression (properly escaped) to exclude specific STIGs from parsing

 --ia               Override any IA controls in the DB to use only the ones that are in the STIG file
 --delete           Delete any files once complete
 --debug            Debugging output
 --help             This screen

EOO;
}
