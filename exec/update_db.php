<?php
/**
 * File: update_db.php
 * Purpose: Script to download updated versions of the online files and update the database
 * Author: Ryan Prather
 * Created: Jan 5, 2015
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
 * - Apr 29, 2018 - Added extract parameter to only extract nasl archive file, fixed a couple bugs
 * - May 10, 2018 - Removed ping of cve.mitre.org, and added 'po' and 'do' parameters for NVD CVE
 * - Jun 5, 2018 - Fixed a couple setting updates
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

$cmd = getopt("h::u::p::", ['cpe::', 'cce::', 'cve::', 'nvd::', 'nasl::', 'stig::', 'do::', 'po::', 'help::', 'debug::', 'extract::', 'exclude::']);

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

if (isset($cmd['debug']) && $cmd['debug']) {
    $log_level = Logger::DEBUG;
}

$stream = new StreamHandler("php://output", $log_level);
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
        $log->emergency("Cannot connect to internet");
    }
}

/**
 * Update CPE content downloaded from NIST
 */
if (isset($cmd['cpe'])) {
    $db->set_Setting_Array([
        'cpe-dl-progress' => 0,
        'cpe-progress'    => 0,
        'cpe-count'       => 0
    ]);

    $path = TMP . "/cpe";
    if (isset($cmd['p']) && $cmd['p']) {
        $path = $cmd['p'];
    }

    check_path($path);

    $diff->resetClock();
    print "Started CPE ingestion ({$diff->getStartClockTime()})" . PHP_EOL;

    // search for an unzip any zip files in the tmp directory
    $zip_files = glob("{$path}/*cpe-dictionary*.zip");
    if (count($zip_files)) {
        $log->debug("Found a existing cpe-dictionary.zip file, unzipping then parsing");
        $zip = new ZipArchive();
        foreach ($zip_files as $file) {
            $log->debug("Unzipping {$file}");
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
                $name = "cpe-dictionary-{$diff->getStartClock()->format("Ymd")}.xml";
            }
            rename($fname, "{$path}/{$name}");
        }
    }

    $cpe_fname       = realpath($path) . "/cpe-dictionary-{$current_date->format('Ymd')}.xml";
    $cpe_url         = "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml";
    $cpe_parse_fname = null;

    // download the file if the do flag is used even if it already exists
    if (isset($cmd['do']) && !isset($cmd['po'])) {
        download_file($cpe_url, $cpe_fname, $db->help, 'cpe-dl-progress');
    }
    // download the file only if it doesn't exist
    elseif (!file_exists($cpe_fname) && !isset($cmd['po'])) {
        download_file($cpe_url, $cpe_fname, $db->help, 'cpe-dl-progress');
    }
    elseif (!isset($cmd['po'])) {
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
            $log->warning("Could not find a CPE file to parse");
        }

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/parse_cpe.php") . " --" .
            " -f=\"" . realpath($cpe_parse_fname) . "\"" .
            " -d=\"{$dt->format("Y-m-d")}\"";

        $log->debug("Running CPE parsing script on file: $cpe_parse_fname");
        passthru($script);
    }

    $db->help->select_count("software");
    $cpe_count = $db->help->execute();

    $db->set_Setting("cpe-count", $cpe_count);

    $diff->stopClock();

    print PHP_EOL . "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total time: {$diff->getDiffString()}" . PHP_EOL;

    sleep(3);
}

/**
 * Update CVE content
 */
if (isset($cmd['cve'])) {
    $db->set_Setting_Array([
        'nvd-cve-dl-progress' => 0,
        'nvd-cve-progress'    => 0,
        'nvd-cve-count'       => 0,
        'cve-dl-progress'     => 0,
        'cve-progress'        => 0,
        'cve-count'           => 0
    ]);
    $path = TMP . "/cve";
    if (isset($cmd['p']) && $cmd['p']) {
        $path = $cmd['p'];
    }

    check_path($path);

    $diff->resetClock();
    print "Started CVE ingestion {$diff->getStartClockTime()}" . PHP_EOL;

    $cve_files = glob(TMP . "/allitems.xml");
    if (count($cve_files)) {
        foreach ($cve_files as $file) {
            rename($file, "{$path}/cve-all-{$diff->getStartClock()->format("Ymd")}.xml");
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

    if (isset($cmd['do']) && !isset($cmd['po'])) {
        download_file($cve_url, $cve_fname, $db->help, 'cve-dl-progress');
    }
    elseif (!file_exists($cve_fname) && !isset($cmd['po'])) {
        download_file($cve_url, $cve_fname, $db->help, 'cve-dl-progress');
    }
    elseif (!isset($cmd['po'])) {
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
            $log->error("Could not find a CVE file to parse");
            die;
        }

        $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
            " -c " . realpath(PHP_CONF) .
            " -f " . realpath(DOC_ROOT . "/exec/parse_cve.php") . " --" .
            " -f=\"" . realpath($cve_parse_fname) . "\"" .
            " -d=\"{$dt->format("Y-m-d")}\"";

        $log->debug("Script to run $script");
        passthru($script);
    }

    $db->help->select_count("sagacity.cve_db");
    $cve_count = $db->help->execute();

    $db->set_Setting_Array([
        'cve-dl-progress'     => 100,
        'cve-progress'        => 100,
        'cve-count'           => $cve_count,
        'cve-load-date'       => new DateTime(),
        'nvd-cve-dl-progress' => 100,
        'nvd-cve-progress'    => 100,
        'nvd-cve-count'       => $cve_count,
        'nvd-cve-load-date'   => new DateTime()
    ]);

    $diff->stopClock();

    print "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total Time: {$diff->getDiffString()}" . PHP_EOL;

    sleep(3);
}

/**
 * Update to NVD CVE content
 */
if (isset($cmd['nvd'])) {
    $db->set_Setting_Array([
        'nvd-cve-dl-progress' => 0,
        'nvd-cve-progress'    => 0,
        'nvd-cve-count'       => 0,
        'cve-dl-progress'     => 0,
        'cve-progress'        => 0,
        'cve-count'           => 0
    ]);
    $path = TMP . "/nvd";
    if (isset($cmd['p']) && $cmd['p']) {
        $path = $cmd['p'];
    }
    check_path($path);

    $diff->resetClock();
    print "Started NVD CVE ingestion ({$diff->getStartClockTime()})" . PHP_EOL;

    $nvd_years = [];
    for ($x = 2002; $x <= $diff->getStartClock()->format("Y"); $x++) {
        $nvd_years[] = $x;
    }

    if (isset($cmd['do']) || !isset($cmd['po'])) {
        $too_old = new DateTime();
        $too_old->sub(DateInterval::createFromDateString("7 days"));

        $load_date = new DateTime($db->get_Settings("nvd-cve-load-date"));
        if ($load_date < $too_old) {
            // More than 7 days old so have to do a full load
            foreach ($nvd_years as $yr) {
                $db->set_Setting('nvd-year', $yr);
                download_file("https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{$yr}.json.zip", TMP . "/nvd/nvdcve-{$yr}.json.zip", $db->help, 'nvd-cve-dl-progress');
                $zip = new ZipArchive();
                $zip->open(TMP . "/nvd/nvdcve-{$yr}.json.zip");
                $zip->extractTo(TMP . "/nvd");
                $zip->close();
                unlink(TMP . "/nvd/nvdcve-{$yr}.json.zip");
            }
        }
        else {
            $db->set_Setting('nvd-year', 'modified');
            download_file("https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip", TMP . "/nvd/nvdcve-modified.json.zip", $db->help, 'nvd-cve-dl-progress');
            $zip = new ZipArchive();
            $zip->open(TMP . "/nvd/nvdcve-modified.json.zip");
            $zip->extractTo(TMP . "/nvd");
            $zip->close();
            unlink(TMP . "/nvd/nvdcve-modified.json.zip");

            $db->set_Setting('nvd-year', 'recent');
            download_file("https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip", TMP . "/nvd/nvdcve-recent.json.zip", $db->help, 'nvd-cve-dl-progress');
            $zip->open(TMP . "/nvd/nvdcve-recent.json.zip");
            $zip->extractTo(TMP . "/nvd");
            $zip->close();
            unlink(TMP . "/nvd/nvdcve-recent.json.zip");
        }
    }

    chdir(DOC_ROOT . "/exec");
    if (isset($cmd['po']) || !isset($cmd['do'])) {
        $json_files = glob(TMP . "/nvd/*.json");
        foreach ($json_files as $j) {
            $match = [];
            if (preg_match("/(\d{4}|recent|modified)/", basename($j), $match)) {
                $db->set_Setting('nvd-year', $match[1]);
            }
            else {
                $db->set_Setting('nvd-year', null);
            }
            $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
                " -c " . realpath(PHP_CONF) .
                " -f " . realpath(DOC_ROOT . "/exec/parse_nvd_json_cve.php") . " --" .
                " -f=\"" . realpath($j) . "\"";

            $log->debug("Running NVD CVE parsing script on file: $j");
            passthru($script);
        }
    }

    $db->help->select_count("sagacity.cve_db");
    $nvd_count = $db->help->execute();

    $diff->stopClock();
    print "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total time {$diff->getTotalDiffString()}" . PHP_EOL;

    $db->set_Setting_Array([
        'nvd-cve-load-date'   => $diff->getEndClock()->format(MYSQL_DT_FORMAT),
        'nvd-cve-count'       => $nvd_count,
        'nvd-cve-progress'    => 100,
        'nvd-cve-dl-progress' => 100,
        'nvd-year'            => null,
        'cve-load-date'       => $diff->getEndClock()->format(MYSQL_DT_FORMAT),
        'cve-count'           => $nvd_count,
        'cve-progress'        => 100,
        'cve-dl-progress'     => 100
    ]);
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
    $db->set_Setting_Array([
        'nasl-dl-progress' => 0,
        'nasl-progress'    => 0,
        'nasl-count'       => 0
    ]);

    // Capture start time for performance monitoring
    $diff->resetClock();
    print "Started NASL ingestion ({$diff->getStartClockTime()})" . PHP_EOL;

    // Generate a unique filename for the OpenVAS feed archive using the current date
    $nasl_fname = TMP . "/nessus_plugins/nasl_plugins-{$current_date->format("Ymd")}.tar.bz2";

    // Download OpenVAS feed if a) it doesn't exist, b) can reach openvas.org, and c) parse only flag not set
    if (!file_exists($nasl_fname) && ping("openvas.org") && !isset($cmd['po'])) {
        $log->debug("Downloading new NASL library");
        download_file("http://www.openvas.org/openvas-nvt-feed-current.tar.bz2", $nasl_fname, $db->help, 'nasl-dl-progress');
    }

    // Can only extract .tar.bz2 files on Linux so...
    if (!isset($cmd['do']) || isset($cmd['po'])) {
        if (file_exists($nasl_fname)) {
            if (substr(strtolower(PHP_OS), 0, 3) == 'lin') {
                $log->debug("Extracting NASL files from archive");
                passthru("tar xvf $nasl_fname -C " . realpath(TMP . "/nessus_plugins") .
                    " --wildcards --transform='s/.*\///' '*.nasl'");

                if (isset($cmd['extract'])) {
                    print "Completed extracting files from archive" . PHP_EOL;
                }
            }
        }

        if (isset($cmd['extract'])) {
            die;
        }

        // ...if there are no .nasl files in the directory, die and give instructions for unzipping in Windows
        $files = glob(TMP . "/nessus_plugins/*.nasl");
        if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
            if (file_exists(getenv("%ProgramData%") . "/Tenable/Nessus/nessus/plugins")) {
                $log->debug("Importing local Nessus plugin files");
                $files = array_merge($files, glob(getenv("%ProgramData%") . "/Tenable/Nessus/nessus/plugins/*.nasl"));
            }
        }
        elseif (strtolower(substr(PHP_OS, 0, 3)) == 'lin') {
            if (file_exists("/opt/nessus/lib/nessus/plugins") && is_readable("/opt/nessus/lib/nessus/plugins")) {
                $log->debug("Importing local Nessus plugin files");
                $files = array_merge($files, glob("/opt/nessus/lib/nessus/plugins/*.nasl"));
            }

            if (file_exists("/opt/sc/data/nasl") && is_readable("/opt/sc/data/nasl")) {
                $log->debug("Importing local Nessus plugin files");
                $files = array_merge($files, glob("/opt/sc/data/nasl/*.nasl"));
            }
        }
        $files = array_unique($files);

        if (!($file_count = count($files))) {
            $log->emergency("Downloaded the OpenVAS NVT plugin repository, please extract *.nasl files to " . realpath(TMP . "/nessus_plugins") . PHP_EOL .
                "If you have Bash on Windows ({path} = /mnt/c/xampp/www) or Cygwin ({path} = /cygdrive/c/xampp/www) installed you can run the following command on the downloaded file tweaking the paths" . PHP_EOL .
                "tar xvf {path}/tmp/nessus_plugins/" . basename($nasl_fname) . " -C {path}/tmp/nessus_plugins --wildcards --transform='s/.*\///' '*.nasl'" . PHP_EOL);
            die;
        }

        // Report how many NASL files were found in the directory
        print "Found {$file_count} NASL files" . PHP_EOL . "Started at {$diff->getStartClockTime()}" . PHP_EOL;

        // Query database to build an array of existing plugins to compare against on import
        $existing_plugins = [];
        $db->help->select("nessus_plugins", ['plugin_id', 'file_date']);
        $rows             = $db->help->execute();
        if (is_array($rows) && count($rows)) {
            foreach ($rows as $row) {
                $existing_plugins[$row['plugin_id']] = DateTime::createFromFormat("U", $row['file_date']);
            }
        }
        $log->debug("Count of existing plugins " . count($existing_plugins));

        // Sort the files and loop over them
        natsort($files);
        foreach ($files as $file) {
            // Read the current NASL file into a nasl object
            $nasl = new nasl($file);

            // calculate percent complete
            $comp = number_format(($total_complete / $file_count) * 100, 2);
            print "\r{$comp}%";
            $log->debug("Parsing {$file} ({$comp}%)");

            // If no plugin ID, delete file and continue to the next plugin
            if (!isset($nasl->id)) {
                $log->warning("Could not locate an ID in the plugin, skipping");
                unlink($file);
                continue;
            }

            // Only process if plugin doesn't already exist or has an older last_modificaiton date
            if (!isset($existing_plugins[$nasl->id]) ||
                (isset($nasl->last_modification) && $existing_plugins[$nasl->id] > $nasl->last_modification)) {
                $log->info("Updating plugin {$nasl->id}");

                // define command line to call script to parse the file
                $script = realpath(defined('PHP_BIN') ? PHP_BIN : PHP) .
                    " -c " . realpath(PHP_CONF) .
                    " -f " . realpath(DOC_ROOT . "/exec/nessus-plugin-to-database.php") . " --" .
                    " -f=\"{$file}\"";

                $threads[] = new \Cocur\BackgroundProcess\BackgroundProcess($script);
                end($threads)->run();

                $count++;
                $total_complete++;

                if($total_complete % 100 == 0) {
                    $db->set_Setting('nasl-progress', $comp);
                }
            }
        }
    }

    $db->set_Setting_Array([
        'nasl-dl-progress' => 100,
        'nasl-progress'    => 100,
        'nasl-count'       => $total_complete,
        'nasl-load-date'   => new DateTime()
    ]);

    $diff->stopClock();

    print PHP_EOL . "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total Time: {$diff->getDiffString()}" . PHP_EOL;

    sleep(3);
}

/**
 * Update STIG library from DISA content
 */
if (isset($cmd['stig'])) {
    $db->set_Setting_Array([
        'stig-dl-progress' => 0,
        'stig-progress'    => 0,
        'stig-count'       => 0
    ]);
    $path = TMP . "/stigs";
    check_path($path);

    $diff->resetClock();
    print "Started STIG ingestion ({$diff->getStartClockTime()})" . PHP_EOL;

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
            $log->debug("Checking for $url");
            if (url_exists($url)) {
                download_file($url, $stig_fname, $db->help, 'stig-dl-progress');
            }
        }
        else {
            $log->debug("Checking for $current_url");
            if ($found = url_exists($current_url)) {
                download_file($current_url, $stig_fname, $db->help, 'stig-dl-progress');
            }

            if (!$found) {
                $log->debug("Checking for $current_v2_url");
                if ($found = url_exists($current_v2_url)) {
                    download_file($current_v2_url, $stig_fname, $db->help, 'stig-dl-progress');
                }
            }

            if ($mon == '01') {
                $year--;
            }
            $prev_url    = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_{$year}_{$prev_mon}.zip";
            $prev_v2_url = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_{$year}_{$prev_mon}_v2.zip";

            if (!$found) {
                $log->debug("Checking for $prev_url");
                if ($found = url_exists($prev_url)) {
                    download_file($prev_url, $stig_fname, $db->help, 'stig-dl-progress');
                }
            }

            if (!$found) {
                $log->debug("Checking for $prev_v2_url");
                if (url_exists($prev_v2_url)) {
                    download_file($prev_v2_url, $stig_fname, $db->help, 'stig-dl-progress');
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
            (isset($cmd['exclude']) && $cmd['exclude'] ? " --exclude=\"{$cmd['exclude']}\"" : "") .
            " --delete";

        $log->debug("Script to run $script");
        passthru($script);
    }

    $db->help->select_count("sagacity.stigs");
    $stig_count = $db->help->execute();

    $db->set_Setting("stig-count", $stig_count);

    $diff->stopClock();

    print PHP_EOL . "Finished at {$diff->getEndClockTime()}" . PHP_EOL .
        "Total Time: {$diff->getDiffString()}" . PHP_EOL;

    sleep(3);
}

if (is_a($diff->getTotalDiff(), 'DateInterval')) {
    print "Total Script Time: {$diff->getTotalDiffString()}" . PHP_EOL;
}

/**
 * Usage information about the script
 */
function usage()
{
    $tmp = realpath(TMP);
    print <<<EOO
Purpose: The purpose of this script is to update the CVE, CPE, and CCE databases.  Script will sleep for 3 seconds between actions to allow you review the results.

Usage: php update_db.php [--cpe] [--cve] [--nvd] [--nasl] [--stig] [-u={URL}] [--do] [--po] [-h|--help] [--debug] [--exclude="ex1"]

 --cpe          To download and update the CPE catalog
 --cve          To download and update the CVE catalog using Mitre's database
 --nvd          To download and update the CVE catalog using the National Vulnerability Database (NVD) JSON library
 --nasl         To download OpenVAS NVT library and update NASL files
                    You can also extract *.nasl files from the Nessus library to $tmp/nessus_plugins and it will include these in the update
 --stig         To download and update the STIG library

 --do           To download the files only...do not call the parsers will overwrite any existing files
 --po           To parse the downloaded files only, do not download

 --exclude="ex1"  Insert a valid regex expression (properly escaped) to exclude specific STIGs from parsing (no '/' necessary)
 --extract      Used so script will download and extract files from archive and stop processing

 -u={url}       Used only for STIGs because sometimes DISA will use a non-standard link which makes it difficult to download the file.

 -h|--help      This screen
 --debug        To print verbose debugging messages to the console

EOO;
}
