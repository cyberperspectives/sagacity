<?php

/**
 * File: nasl.inc
 * Author: Ryan Prather
 * Purpose: Class to store data from
 * Created: Jan 15, 2017
 *
 * Copyright 2017: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jan 15, 2017 - File created
 *  - Jan 31, 2017 - Completed parse testing
 *  - Feb 15, 2017 - Fix bug if last modification or creation date are not formatted correctly
 *  - Feb 21, 2017 - Changed throwing exception to just print error and return
 *  - Apr 5, 2017 - Removed deleting NASL file from within class...now happens in wrapper code
 *  - Jun 27, 2017 - Matt Shuter: Added fix for deprecated plugins (#262 & #270)
 */

/**
 * Class to parse NVT .nasl files from OpenVAS and Nessus
 */
class nasl {

  /**
   * Constructor
   *
   * @param string $file
   */
  public function __construct($file = null) {
    if (!is_null($file) && file_exists($file)) {
      $this->parse($file);
    }
  }

  /**
   * Parsing function
   *
   * @param string $file
   *
   * @return boolean
   */
  public function parse($file) {
    $file_contents = null;
    if (file_exists($file)) {
      $file_contents = file_get_contents($file);
    }
    else {
      print "\tCould not find file {$file}" . PHP_EOL;
      return false;
    }

    // Capture regex matches for parsing
    $match = array();

    // Check to see if the plugin is disabled/deprecated and if so, return
    if (preg_match("/Disabled on ([\d\/]+)|@DEPRECATED@/i", $file_contents)) {
      print "\tPlugin file $file is DISABLED" . PHP_EOL;
      return false;
    }

    if (preg_match("/script_id\(([\d\.]+)\)/", $file_contents, $match)) {
      $this->{'id'} = $match[1];
    }
    elseif (preg_match("/script_oid\(\"([\d\.]+)\"\)/", $file_contents, $match)) {
      $this->{'oid'} = $match[1];
      $oid = explode(".", $match[1]);
      $this->{'id'} = end($oid);
    }
    elseif (preg_match("/script_o?id\(([^\)]+)\)/", $file_contents, $match)) {
      preg_match("/" . preg_quote($match[1], "/") . "[^\"]+\"([^\"]+)\"/", $file_contents, $match);

      $this->{'oid'} = $match[1];
      $oid = explode(".", $match[1]);
      $this->{'id'} = end($oid);
    }
    else {
      print "\tCould not find an ID in $file" . PHP_EOL;
      return false;
    }

    if (preg_match("/script_version\(\"[^\d]+([\d\.]+)[^\n]+/", $file_contents, $match)) {
      $this->{'rev'} = $match[1];
    }

    if (preg_match("/script_cvs_date\([^\d]+([\d\-\/]+)/", $file_contents, $match)) {
      try {
        $this->{'last_modification'} = new DateTime($match[1]);
      }
      catch (Exception $e) {
        die(print_r($e, true));
      }
    }

    if (preg_match("/script_set_attribute\([^\"]+\"plugin_publication_date\"[^\"]+\"([\d\/]+)\"/", $file_contents, $match)) {
      try {
        $this->{'creation_date'} = new DateTime($match[1]);
      }
      catch (Exception $e) {
        die(print_r($e, true));
      }
    }

    if (preg_match("/script_set_cvss_base_vector\(\"([^\"]+)\"/", $file_contents, $match)) {
      $this->{'cvss_base_vector'} = $match[1];
    }

    if (preg_match("/script_name\(([^\"]+)?\"([^\"]+)\"\)/", $file_contents, $match)) {
      $this->{'name'} = $match[2];
    }

    if (preg_match("/script_category\(([^\)]+)\)/", $file_contents, $match)) {
      $this->{'cat'} = $match[1];
    }

    if (preg_match("/script_copyright\(([^\"]+)?\"([^\"]+)\"\)/", $file_contents, $match)) {
      $this->{'copyright'} = $match[2];
    }

    if (preg_match("/script_family\(([^\"]+)?\"([^\"]+)\"\)/", $file_contents, $match)) {
      $this->{'family'} = $match[2];
    }

    if (preg_match("/script_summary\(([^\"]+)?\"([^\"]+)\"\)/", $file_contents, $match)) {
      $this->{'summary'} = $match[2];
    }

    if (preg_match("/script_require_ports\(([^\d]+)?([\d]+)\)/", $file_contents, $match)) {
      $this->{'protocol'} = explode(',', str_replace(array('"', ' '), '', $match[2]));
      if (count($this->protocol) == 1) {
        $this->protocol = $this->protocol[0];
      }
    }

    if (preg_match("/CPE ?\= ?\"([^\"]+)\"/", $file_contents, $match)) {
      $this->{'cpe'} = $match[1];
    }

    if (preg_match("/script_set_attribute/", $file_contents)) {
      if (preg_match_all("/script_set_attribute\(([^a]+)?attribute:\"([^\"]+)\",([^v]+)?value:([^\"]+)?\"([^\"]+)\"/", $file_contents, $match)) {
        foreach ($match[2] as $key => $val) {
          if ($val == 'cpe') {
            $this->{$val}[] = str_replace("p-cpe", "cpe", $match[5][$key]);
          }
          else {
            $this->{$val} = $match[5][$key];
          }
        }
      }
    }

    if (preg_match("/script_cve_id\(([^\)]+)\)/", $file_contents, $match)) {
      if (($pos = strpos($match[1], ",")) !== false) {
        $this->{'ref'}['cve'] = explode(',', str_replace(array(' ', '"'), "", $match[1]));
      }
      else {
        $this->{'ref'}['cve'] = array(0 => str_replace(array(" ", '"'), "", $match[1]));
      }
    }

    if (preg_match("/script_bugtraq_id\(([\d]+)/", $file_contents, $match)) {
      if (($pos = strpos($match[1], ",")) !== false) {
        $this->{'ref'}['bug'] = explode(",", str_replace(array(' ', '"'), "", $match[1]));
      }
      else {
        $this->{'ref'}['bug'] = array(0 => $match[1]);
      }
    }

    if (preg_match("/script_cwe_id\(([^\)]+)\)/", $file_contents, $match)) {
      if (($pos = strpos($match[1], ",")) !== false) {
        $this->{'ref'}['cwe'] = explode(",", str_replace(array(' '), '', $match[1]));
      }
      else {
        $this->{'ref'}['cwe'] = array(0 => $match[1]);
      }
    }

    if (preg_match("/script_osvdb_id\(([\d\, ]+)\)/", $file_contents, $match)) {
      if (($pos = strpos($match[1], ",")) !== false) {
        $this->{'ref'}['osvdb'] = explode(",", str_replace(" ", "", $match[1]));
      }
      else {
        $this->{'ref'}['osvdb'] = array(0 => $match[1]);
      }
    }

    $script_xrefs = preg_grep("/script_xref/", explode("\n", $file_contents));

    if (count($script_xrefs)) {
      foreach ($script_xrefs as $y) {
        if (preg_match("/([^\"]+)\"\)\;$/", $y, $match)) {
          if (substr($match[1], 0, 4) == 'http') {
            $this->{'ref'}["URL"][] = $match[1];
          }
          else {
            $val = $match[1];
            if (preg_match("/script_xref\([^\"]+\"([^\"]+)\"/", $y, $match)) {
              $this->{'ref'}[$match[1]][] = $val;
            }
          }
        }
      }
    }

    if (preg_match_all("/script_tag\(([^\"]+)?\"([^\"]+)\"[^v]+value *: *([^\)\(]+)/", $file_contents, $match)) {
      $match2 = array();
      foreach ($match[2] as $key => $val) {
        if (strpos($match[3][$key], '"') !== false) {
          $this->{$val} = str_replace('"', '', $match[3][$key]);
        }
        elseif (preg_match("/" . preg_quote($match[3][$key], "/") . " [^\"]+\"([^\"]+)\"/", $file_contents, $match2)) {
          $this->{$val} = $match2[1];
        }
      }
    }

    if (preg_match_all("/script_tag\(([^\"]+)?\"([^\"]+)\"[^\"]+\"([^\"]+)/", $file_contents, $match)) {
      $dt = array();
      foreach ($match[2] as $key => $val) {
        if ($val == 'creation_date') {
          if (preg_match("/^([\d\/\-\+\ \:]+)/", $match[3][$key], $dt)) {
            try {
              $this->{$val} = new DateTime($dt[1]);
            }
            catch (Exception $e) {
              if (preg_match("/\+05340/", $dt[1], $match)) {
                $this->{$val} = new DateTime(substr($dt[1], 0, -7) . "+0530");
              }
            }
          }
        }
        elseif ($val == 'last_modification') {
          if (preg_match("/: ([\d\-\/\ \+\:]+)/", $match[3][$key], $dt)) {
            try {
              $this->{$val} = new DateTime($dt[1]);
            }
            catch (Exception $e) {
              die(print_r($e, true));
            }
          }
        }
        elseif (!isset($this->{$val})) {
          $this->{$val} = $match[3][$key];
        }
      }
    }

    return true;
  }

}
