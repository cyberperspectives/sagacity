<?php
/**
 * File: update_db.php
 * Purpose: Script to download updated versions of the online files and update the database
 * Author: Ryan Prather
 * Created: Jan 5, 2015
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 * - Jan 5, 2015 - File Created
 * - Sep 1, 2016 - Copyright Updated and added file header
 * - Oct 24, 2016 - Added check for presence of /tmp/cce, /tmp/cve, & /tmp/cpe directories before downloading
 * - Nov 9, 2016 - Added command line parameters for each of the update types (CVE, CPE, CCE),
 *                 Added detection if the file from same day already exists, added "download only" option,
 *                 Added mkdir if temporary directories don't exist, added usage output,
 *                 Changed URL for CCE and CPE to HTTPS paths
 * - Nov 21, 2016 - Cleaned up code a little and added 3 second sleep between commands so user can see results
 * - Dec 7, 2016 - Changed PHP constant to PHP_BIN
 * - Jan 30, 2017 - Updated to parse Nessus NASL plugin update file
 * - Jan 31, 2017 - Completed NASL plugin parsing
 * - Feb 15, 2017 - Completed adding STIG download and update, added parse only (po) flag for offline systems,
 *                  Added ping method to check for connection to internet. Added url_exists method to check for presence of file before attempting to download.
 * - Feb 21, 2017 - Extended output for nasl on Windows hosts, store existing plugins in memory to speed up processing,
 *                  Delete files if there are parsing errors, added --delete flag when parsing stigs,
 *                  Added check to see if STIG file has been downloaded already today
 * - Mar 3, 2017 - Fixed output of tar command like Jeff suggested, and clarified -u parameter
 * - Mar 8, 2017 - Added check for presence of downloaded files before attempting to parse
 * - Mar 13, 2017 - Cleaned up downloads of STIG compilation file, added check for *v2.zip file
 * - Mar 17, 2017 - Added check for previous STIG file that contains '_v2' at the end of the file,
 *                  Added check for any other *.zip files in the /tmp folder just in case user only wants to upgrade FOUO files or individual XML files
 * - Mar 20, 2017 - Added check for previous STIG that includes '_v2' at end of filename, and added checks to fix issues when FOUO file is present
 * - Mar 22, 2017 - Added check for extracted STIG files in /tmp/stig/xml/*.xml
 * - Apr 5, 2017 - Added check for previous STIG compilation_v2, so will now check for 4 different naming possibilities,
 *                 Extended TIME_WAIT ports to 2000, started time totaling process
 * - Apr 7, 2017 - Fixed typo in printed tar command
 * - May 13, 2017 - Clarified if it cannot access the internet instead of "cannot connect to server"
 *                  Fixed confusion with Cygwin and Bash on Windows paths
 * - Jun 27, 2017 - Matt Shuter: Fixed bug #262 & #270
 * - Dec 27, 2017 - Added database field and download progress flag
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'error.inc';
include_once 'database.inc';
include_once 'DateTimeDiff.php';
include_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;

$current_date  = new DateTime();
$total_time    = null;
$total_diff    = 0;
$summary_stats = [];

$cmd = getopt("h::u::p::", ['cpe::', 'cce::', 'cve::', 'nvd::', 'nasl::', 'stig::', 'do::', 'po::', 'help::']);

$db   = new db();
$diff = new DateTimeDiff();

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

$stream = new StreamHandler("php://output", Logger::INFO);
$stream->setFormatter(new LineFormatter("%datetime% %level_name% %message%" . PHP_EOL, "H:i:s.u"));

$log = new Logger("update_db");
$log->pushHandler(new StreamHandler(LOG_PATH . "/update_db.log", $log_level));
$log->pushHandler($stream);

if (isset($cmd['h'], $cmd['help']) ||
    (!isset($cmd['cpe']) && !isset($cmd['cve']) && !isset($cmd['nasl']) && !isset($cmd['stig']) && !isset($cmd['nvd']))) {
    die(usage());
}

if (isset($cmd['do']) || !isset($cmd['po'])) {
    if (!ping("cyberperspectives.com")) {
        die("Cannot connect to internet" . PHP_EOL);
    }
}

/**
 * Update CPE content downloaded from NIST
 */
if (isset($cmd['cpe'])) {
    $db->set_Setting('cpe-dl-progress', 0);
    $db->set_Setting('cpe-progress', 0);

    $path = TMP . "/cpe";
    if (isset($cmd['p']) && $cmd['p']) {
        $path = $cmd['p'];
    }

    check_path($path);

    $diff->resetClock();
    $log->info("Started CPE ingestion ({$diff->getStartClockTime()})");

    // search for an unzip any zip files in the tmp directory
    $zip_files = glob("{$path}/*cpe-dictionary*.zip");
    if (count($zip_files)) {
        $log->debug("Found a existing cpe-dictionary.zip file, unzipping then parsing");
        $zip = new ZipArchive();
        foreach ($zip_files as $file) {
            $log->info("Unzipping {$file}");
            $zip->open($file);
            $zip->extractTo($path);
            $zip->close();
            unlink($file);
        }
    }

    // search for any existing cpe-dictionary files in the /tmp directory
    $tmp_files = glob(TMP . "/*cpe-dictionary*.xml");
    if (count($tmp_files)) {
        $log->debug("Found existing cpe-dictionary.xml file in TMP folder, moving to TMP/cpe then processing");
        foreach ($tmp_files as $fname) {
            $name = basename($fname);
            if ($name == 'official-cpe-dictionary_v2.3.xml') {
                $name = "cpe-dictionary-{$start_time->format("Ymd")}.xml";
            }
            rename($fname, "{$path}/{$name}");
        }
    }

    $cpe_fname       = realpath($path) . "/cpe-dictionary-{$current_date->format('Ymd')}.xml";
    $cpe_url         = "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml";
    $cpe_parse_fname = null;

    // download the file if the do flag is used even if it already exists
    if (isset($cmd['do']) && ping("nist.gov") && !isset($cmd['po'])) {
        download_file($cpe_url, $cpe_fname, $db, 'cpe-dl-progress');
    }
    // download the file only if it doesn't exist
    elseif (!file_exists($cpe_fname) && ping("nist.gov") && !isset($cmd['po'])) {
        download_file($cpe_url, $cpe_fname, $db, 'cpe-dl-progress');
    }
    elseif (!isset($cmd['po']) && !ping("nist.gov")) {
        $log->error("Could not connect to nist.gov to download the CPE library");
        die();
    }

    $dt = new DateTime();

    if (!isset($cmd['do']) || isset($cmd['po'])) {
        $cpe_files = glob("{$path}/*cpe-dictionary*.xml");
        rsort($cpe_files, SORT_NATURAL);

        if (count($cpe_files)) {
            $match = [];
            if (preg_match("/cpe\-dictionary\-([\d]+)\.xml/", $cpe_files[0], $match)) {
                $dt = DateTime::createFromFormat("Ymd", $match[1]);

                $seven_days_old = new DateTime();
                $seven_days_old->sub(DateInterval::createFromDateString("7 days"));

                if ($dt < $seven_days_old) {
                    $log->warning("The file that is being ingested is more than 7 days old ({$dt->format('Y-m-d')})");
                }

                $cpe_parse_fname = $cpe_files[0];
            }
            else {
                $log->warning("Don't know when the file was downloaded, but parsing it anyway");
                $cpe_parse_fname = $cpe_files[0];
            }
        }

        if (is_null($cpe_parse_fname)) {
            $log->warning("Coult not find a CPE file to parse");
        }

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/parse_cpe.php") . " --" .
            " -f=\"" . realpath($cpe_parse_fname) . "\"" .
            " -d=\"{$dt->format("Y-m-d")}\"";

        $log->info("Running parsing script");
        passthru($script);
    }

    $diff->stopClock();

    $log->info(PHP_EOL . "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total time: {$diff->getDiffString()}");

    sleep(3);
}

/**
 * Update CVE content
 */
if (isset($cmd['cve'])) {
    $db->set_Setting('cve-dl-progress', 0);
    $db->set_Setting('cve-progress', 0);
    $path = TMP . "/cve";
    if (isset($cmd['p']) && $cmd['p']) {
        $path = $cmd['p'];
    }

    check_path($path);

    $diff->resetClock();
    $log->info("Started CVE ingestion {$diff->getStartClockTime()}");

    $cve_files = glob(TMP . "/allitems.xml");
    if (count($cve_files)) {
        foreach ($cve_files as $file) {
            rename($file, "{$path}/cve-all-{$start_time->format("Ymd")}.xml");
        }
    }

    $tmp_files = glob("{$path}/cve*.xml");
    if (count($tmp_files)) {
        foreach ($tmp_files as $fname) {
            rename($fname, "{$path}/" . basename($fname));
        }
    }

    $cve_fname       = realpath($path) . "/cve-all-{$current_date->format('Ymd')}.xml";
    $cve_url         = "http://cve.mitre.org/data/downloads/allitems.xml";
    $cve_parse_fname = null;

    if (isset($cmd['do']) && ping("cve.mitre.org") && !isset($cmd['po'])) {
        download_file($cve_url, $cve_fname, $db, 'cve-dl-progress');
    }
    elseif (!file_exists($cve_fname) && ping("cve.mitre.org") && !isset($cmd['po'])) {
        download_file($cve_url, $cve_fname, $db, 'cve-dl-progress');
    }
    elseif (!isset($cmd['po']) && !ping("cve.mitre.org")) {
        Sagacity_Error::err_handler("Could not connect to cve.mitre.org to download the CVE library", E_ERROR);
    }

    if (!isset($cmd['do']) || isset($cmd['po'])) {
        $cve_files = glob("{$path}/cve-all-*.xml");
        rsort($cve_files, SORT_NATURAL);

        if (count($cve_files)) {
            $match = [];
            if (preg_match("/cve\-all\-([\d]+)\.xml/", $cve_files[0], $match)) {
                $dt = DateTime::createFromFormat("Ymd", $match[1]);

                $seven_days_old = new DateTime();
                $seven_days_old->sub(DateInterval::createFromDateString("7 days"));

                if ($dt < $seven_days_old) {
                    $log->warning("The CVE file that is being ingested is more than 7 days old ({$dt->format('Y-m-d')})");
                }

                $cve_parse_fname = $cve_files[0];
            }
        }

        if (is_null($cve_parse_fname)) {
            $log->error("Coult not find a CVE file to parse");
            die;
        }

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/parse_cve.php") . " --" .
            " -f=\"" . realpath($cve_parse_fname) . "\"" .
            " -d=\"{$dt->format("Y-m-d")}\"";

        $log->info("Script to run $script");
        passthru($script);
    }

    $diff->stopClock();

    $log->info("Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total Time: {$diff->getDiffString()}");

    sleep(3);
}

if (isset($cmd['nvd'])) {
    $db->set_Setting('nvd-cve-dl-progress', 0);
    $db->set_Setting('nvd-cve-progress', 0);
    $path = TMP . "/nvd";
    if (isset($cmd['p']) && $cmd['p']) {
        $path = $cmd['p'];
    }
    check_path($path);

    $diff->resetClock();
    $log->info("Started NVD CVE ingestion ({$diff->getStartClockTime()})");

    $nvd_years = [];
    for ($x = 2002; $x <= $diff->getStartClock()->format("Y"); $x++) {
        $nvd_years[] = $x;
    }

    $too_old = new DateTime();
    $too_old->sub(DateInterval::createFromDateString("7 days"));

    $load_date = new DateTime($db->get_Settings("nvd-cve-load-date"));
    if ($load_date < $too_old) {
        // More than 7 days old so have to do a full load
        foreach ($nvd_years as $yr) {
            download_file("https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{$yr}.json.zip", TMP . "/nvd/nvdcve-{$yr}.json.zip");
            $zip = new ZipArchive();
            $zip->open(TMP . "/nvd/nvdcve-{$yr}.json.zip");
            $zip->extractTo(TMP . "/nvd");
            $zip->close();
            unlink(TMP . "/nvd/nvdcve-{$yr}.json.zip");
        }
    }
    else {
        download_file("https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip", TMP . "/nvd/nvdcve-modified.json.zip");
        $zip = new ZipArchive();
        $zip->open(TMP . "/nvd/nvdcve-modified.json.zip");
        $zip->extractTo(TMP . "/nvd");
        $zip->close();
        unlink(TMP . "/nvd/nvdcve-modified.json.zip");

        download_file("https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip", TMP . "/nvd/nvdcve-recent.json.zip");
        $zip->open(TMP . "/nvd/nvdcve-recent.json.zip");
        $zip->extractTo(TMP . "/nvd");
        $zip->close();
        unlink(TMP . "/nvd/nvdcve-recent.json.zip");
    }

    chdir(DOC_ROOT . "/exec");
    $json_files = glob(TMP . "/nvd/*.json");
    foreach ($json_files as $j) {
        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/parse_nvd_json_cve.php") . " --" .
            " -f=\"" . realpath($j) . "\"";

        $log->info("Running NVD CVE parsing script");
        passthru($script);
    }

    $diff->stopClock();
    $log->info("Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total time {$diff->getTotalDiffString()}");

    $db->set_Setting("nvd-cve-load-date", $diff->getEndClock()->format(MYSQL_DT_FORMAT));
}

/**
 * Update CCE content
 */
if (isset($cmd['cce'])) {
    check_path(TMP . "/cce");

    $cce_fname = TMP . "/cce/cce-all-20130214.xml";

    if (!file_exists($cce_fname) && ping("nist.gov") && !isset($cmd['po'])) {
        download_file("https://static.nvd.nist.gov/feeds/xml/cce/cce-COMBINED-5.20130214.xml", $cce_fname);
    }

    if (!isset($cmd['do']) || isset($cmd['po'])) {

    }

    sleep(3);
}

/**
 * Parse NASL content from NVT and/or Nessus
 */
if (isset($cmd['nasl'])) {
    $db->set_Setting('nasl-dl-progress', 0);
    $db->set_Setting('nasl-progress', 0);
    check_path(TMP . "/nessus_plugins", true);

    // Capture start time for performance monitoring
    $diff->resetClock();
    $log->info("Started NASL ingestion ({$diff->getStartClockTime()})");

    // Generate a unique filename for the OpenVAS feed archive using the current date
    $nasl_fname = TMP . "/nessus_plugins/nasl_plugins-{$current_date->format("Ymd")}.tar.bz2";

    // Download OpenVAS feed if a) it doesn't exist, b) can reach openvas.org, and c) parse only flag not set
    if (!file_exists($nasl_fname) && ping("openvas.org") && !isset($cmd['po'])) {
        download_file("http://www.openvas.org/openvas-nvt-feed-current.tar.bz2", $nasl_fname, $db, 'nasl-dl-progress');
    }

    // Can only extract .tar.bz2 files on Linux so...
    if (!isset($cmd['do']) || isset($cmd['po'])) {
        if (file_exists($nasl_fname)) {
            if (substr(strtolower(PHP_OS), 0, 3) == 'lin') {
                passthru("tar xvf $nasl_fname -C " . realpath(TMP . "/nessus_plugins") .
                    " --wildcards --transform='s/.*\///' '*.nasl'");
            }
        }

        // ...if there are no .nasl files in the directory, die and give instructions for unzipping in Windows
        $files = glob("*.nasl");
        if (!count($files)) {
            die("Downloaded the OpenVAS NVT plugin repository, please extract *.nasl files to " . realpath(TMP . "/nessus_plugins") . PHP_EOL .
                "If you have Bash on Windows ({path} = /mnt/c/xampp/www) or Cygwin ({path} = /cygdrive/c/xampp/www) installed you can run the following command on the downloaded file tweaking the paths" . PHP_EOL .
                "tar xvf {path}/tmp/nessus_plugins/" . basename($nasl_fname) . " -C {path}/tmp/nessus_plugins --wildcards --transform='s/.*\///' '*.nasl'" . PHP_EOL);
        }

        // Report how many NASL files were found in the directory
        $log->info("Found " . count($files) . " NASL files" . PHP_EOL .
            "Started at {$start_time->format("Y-m-d H:i:s")}");

        chdir(DOC_ROOT);

        // Query database to build an array of existing plugins to compare against on import
        $existing_plugins = [];
        $db->help->select("nessus_plugins", ['plugin_id', 'file_date']);
        $rows             = $db->help->execute();
        if (is_array($rows) && count($rows)) {
            foreach ($rows as $row) {
                $existing_plugins[$row['plugin_id']] = DateTime::createFromFormat("U", $row['file_date']);
            }
        }

        // Sort the files and loop over them
        $x = 0;
        natsort($files);
        foreach ($files as $file) {
            $abs_file_path = realpath(TMP . "/nessus_plugins/$file");
            // Read the current NASL file into a nasl object
            $nasl          = new nasl($abs_file_path);

            // Report progress
            $comp = number_format(($x / count($files)) * 100, 2) . "%";
            print "\r$comp";

            // If no plugin ID, delete file and continue to the next plugin
            if (!isset($nasl->id)) {
                unlink($abs_file_path);
                continue;
            }

            // Only process if plugin doesn't already exist or has an older last_modificaiton date
            if (!isset($existing_plugins[$nasl->id]) ||
                (isset($nasl->last_modification) && $existing_plugins[$nasl->id] > $nasl->last_modification)) {

                // define command line to call script to parse the file
                $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
                    " -c " . realpath(PHP_CONF) .
                    " -f " . realpath(DOC_ROOT . "/exec/nessus-plugin-to-database.php") . " --" .
                    " -f=\"" . $abs_file_path . "\"";

                $process = new \Cocur\BackgroundProcess\BackgroundProcess($script);
                $process->run();

                // Call the script w/ shell or exec depending on platform
                if (substr(strtolower(PHP_OS), 0, 3) == 'lin') {
                    $output = [];
                    exec("netstat -an | grep TIME_WAIT | wc -l", $output);
                    if ($output[0] > 2000) {
                        do {
                            $log->notice("\r$comp Sleeping till connections get below 100 {$output[0]}");
                            sleep(1);
                            $output = [];
                            exec("netstat -an | grep TIME_WAIT | wc -l", $output);
                        }
                        while ($output[0] > 100);
                    }
                }
            }
            else {
                unlink($abs_file_path);
            }

            $x++;
        }
    }

    $diff->stopClock();

    $log->info(PHP_EOL . "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total Time: {$diff->getDiffString()}");

    sleep(3);
}

/**
 * Update STIG library from DISA content
 */
if (isset($cmd['stig'])) {
    $db->set_Setting('stig-dl-progress', 0);
    $db->set_Setting('stig-progress', 0);
    $path = TMP . "/stigs";
    check_path($path);

    $diff->resetClock();
    $log->info("Started STIG ingestion ({$diff->getStartClockTime()})");

    $mon      = '01';
    $prev_mon = '10';
    $year     = (int) $current_date->format("Y");

    if (between($current_date->format("n"), 4, 6)) {
        $mon      = '04';
        $prev_mon = '01';
    }
    elseif (between($current_date->format("n"), 7, 9)) {
        $mon      = '07';
        $prev_mon = '04';
    }
    elseif (between($current_date->format("n"), 10, 12)) {
        $mon      = '10';
        $prev_mon = '07';
    }

    $current_url    = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_{$year}_{$mon}.zip";
    $current_v2_url = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_{$year}_{$mon}_v2.zip";

    $stig_fname = "{$path}/stig_library-{$year}_{$mon}.zip";

    if (!file_exists($stig_fname) && ping("disa.mil") && !isset($cmd['po'])) {
        if (isset($cmd['u'])) {
            $url = $cmd['u'];
            $log->info("Checking for $url");
            if (url_exists($url)) {
                download_file($url, $stig_fname, $db, 'stig-dl-progress');
            }
        }
        else {
            $log->info("Checking for $current_url");
            if ($found = url_exists($current_url)) {
                download_file($current_url, $stig_fname, $db, 'stig-dl-progress');
            }

            if (!$found) {
                $log->info("Checking for $current_v2_url");
                if ($found = url_exists($current_v2_url)) {
                    download_file($current_v2_url, $stig_fname, $db, 'stig-dl-progress');
                }
            }

            if ($mon == '01') {
                $year--;
            }
            $prev_url    = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_{$year}_{$prev_mon}.zip";
            $prev_v2_url = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_{$year}_{$prev_mon}_v2.zip";

            if (!$found) {
                $log->info("Checking for $prev_url");
                if ($found = url_exists($prev_url)) {
                    download_file($prev_url, $stig_fname, $db, 'stig-dl-progress');
                }
            }

            if (!$found) {
                $log->info("Checking for $prev_v2_url");
                if (url_exists($prev_v2_url)) {
                    download_file($prev_v2_url, $stig_fname, $db, 'stig-dl-progress');
                }
            }
        }
    }

    if (!isset($cmd['do']) || isset($cmd['po'])) {
        $stig_files = array_merge(
            glob("{$path}/*.zip"), glob("{$path}/*.xml"), glob(TMP . "/*.zip"), glob(TMP . "/*.xml"), glob(TMP . "/stigs/xml/*.xml")
        );
        if (!file_exists($stig_fname) && !count($stig_files)) {
            die("Could not locate $stig_fname or find any other zip files in " . realpath(TMP));
        }

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/background_stigs.php") . " --" .
            " --delete";

        $log->info("Script to run $script");
        passthru($script);
    }

    $diff->stopClock();

    $log->info(PHP_EOL . "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total Time: {$diff->getDiffString()}");

    sleep(3);
}

if (is_a($diff->getTotalDiff(), 'DateInterval')) {
    $log->info("Total Script Time: {$diff->getTotalDiffString()}");
}

/**
 *
 */
function usage()
{
    $tmp = TMP;
    print <<<EOO
Purpose: The purpose of this script is to update the CVE, CPE, and CCE databases.  Script will sleep for 3 seconds between actions to allow you review the results.

Usage: php update_db.php [--cpe] [--cve] [--nasl] [--stig] [-u={URL}] [--do] [--po] [-h|--help]

 --cpe          To download and update the CPE catalog
 --cve          To download and update the CVE catalog
 --nasl         To download OpenVAS NVT library and update NASL files
                    You can also extract *.nasl files from the Nessus library to $tmp/nessus_plugins and it will include these in the update
 --stig         To download and update the STIG library
 --do           To download the files only...do not call the parsers will overwrite any existing files
 --po           To parse the downloaded files only, do not download

 -u={url}       [optional] Used only for STIGs because sometimes DISA will use a non-standard link which makes it difficult to download the file.

 -h|--help      This screen

EOO;
}
