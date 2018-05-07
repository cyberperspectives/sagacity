<?php
/*
  Server-side PHP file upload code for HTML5 File Drag & Drop demonstration
  Featured on SitePoint.com
  Developed by Craig Buckler (@craigbuckler) of OptimalWorks.net

  Change Log:
  - 11 June 2014 - Added ability for host data files to be sent to specific directory tmp/data_collection/{hostname}
  - Jun 3, 2015 - Copyright Updated
 * - Apr 15, 2017 - Add FileDetection for imported files and added display file type in UI after upload
 * - Dec 27, 2017 - Reordered order of moved file detection to before file move to prevent uploading unapproved files (e.g. php)
 * - Jan 8, 2018 - Fixed order bug
 */

include_once 'config.inc';
require_once 'helper.inc';

set_time_limit(0);

$fn = filter_input(INPUT_SERVER, 'HTTP_X_FILENAME', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$ft = new DateTime(filter_input(INPUT_SERVER, 'HTTP_X_FILEMTIME', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE));

if (!is_uploaded_file($_FILES['file']['tmp_name'])) {
    error_log("Failed to upload {$_FILES['file']['name']}");
    die;
}

if ($fn) {
    move_uploaded_file($_FILES['file']['tmp_name'], TMP . "/" . basename($fn));
    if (is_a($ft, 'DateTime')) {
        touch(realpath(TMP . "/" . basename($fn)), $ft->getTimestamp());
    }

    $file_type = FileDetection(TMP . "/" . $fn);

    switch ($file_type['type']) {
        case SCC_XCCDF:
            print header(JSON) . json_encode(['imageUrl' => "/img/scan_types/scc.png"]);
            break;
        case GOLDDISK:
            print header(JSON) . json_encode(['imageUrl' => "/img/scan_types/gold-disk.png"]);
            break;
        case NMAP_XML:
        case NMAP_TEXT:
        case NMAP_GREPABLE:
            print header(JSON) . json_encode(['imageUrl' => "/img/scan_types/nmap.png"]);
            break;
        case NESSUS:
            print header(JSON) . json_encode(['imageUrl' => "/img/scan_types/nessus.png"]);
            break;
        case MBSA_XML:
        case MBSA_TEXT:
            print header(JSON) . json_encode(['imageUrl' => "/img/scan_types/mbsa.png"]);
            break;
        case STIG_VIEWER_CKL:
            print header(JSON) . json_encode(['imageUrl' => "/img/scan_types/stig-viewer.png"]);
            break;
        case TECH_ECHECKLIST_EXCEL:
            print header(JSON) . json_encode(['imageUrl' => '/img/scan_types/echecklist.png']);
            break;
        default:
            print header(JSON) . json_encode(['imageUrl' => null]);
            unlink(TMP . "/" . basename($fn));
    }
} else {
    error_log("Error uploading file {$_FILES['file']['name']}");
}
