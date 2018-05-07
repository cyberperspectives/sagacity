<?php

/**
 * File: parse_cpe.php
 * Author: Ryan Prather
 * Purpose: Script to parse CPE library
 * Created: Jul 28, 2014
 *
 * Portions Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Jul 28, 2014 - File created
 *  - Sep 1, 2016 - Copyright Updated and converted to constants
 *  - Nov 11, 2016 - Comments added by Ryan Prather and Matt Shuter
 *  - Nov 21, 2016 - Added print out to display the number of new CPEs imported
 *  - Jan 30, 2017 - Added short string for software and conversions to translate some of the more popular software (MS Windows, RedHat ELS, and OpenSuSE)
 *  - Feb 15, 2017 - Formatting and migrated to use the new db_helper functions
 *  - Apr 5, 2017 - Removed MS manufacture name from Microsoft owned software for shortened software string
 */
$cmd = getopt("f:d:", ['debug::', 'help::']);

if (!isset($cmd['f']) || isset($cmd['help'])) {
  die(usage());
}
elseif (!file_exists($cmd['f'])) {
  die("Could not find {$cmd['f']}\n");
}

include_once 'config.inc';
include_once 'database.inc';
include_once 'helper.inc';
include_once 'xml_parser.inc';

chdir(TMP);
set_time_limit(0);

class cpe_parser extends basic_xml_parser {

  /**
   * The CPE that is currently being parsed
   *
   * @var string
   */
  var $cpe;

  /**
   * The CPE v2.3 formatted string of the CPE that is currently being parsed
   *
   * @var string
   */
  var $cpe23;

  /**
   * An array to represent the CPE
   *
   * @var array
   */
  var $cpe_arr;

  /**
   * The software title string associated with the CPE that is currently being parsed
   *
   * @var string
   */
  var $sw_string;

  /**
   * Variable to store a short software string
   *
   * @var string
   */
  var $short_string;

  /**
   * The counter that tracks how many cpe_items we've processed
   *
   * @var int
   */
  var $count;

  /**
   * Counter for the number of new CPEs
   *
   * @var number
   */
  var $new;

  /**
   * Counter for the number of deleted CPEs
   *
   * @var number
   */
  var $deleted;

  /**
   * Variable to store existing CPEs
   *
   * @var array
   */
  var $existing_cpes;

  /**
   * Array to store list of CPEs to delete from database
   *
   * @var array
   */
  var $cpes_to_remove;

  /**
   * Array to store new CPEs to add to DB
   *
   * @var array
   */
  var $new_cpes;

  /**
   * Variable to store the total number of CPEs to parse
   *
   * @var int
   */
  var $total_cpes;

  /**
   * Constructor
   *
   * @param string $xml_fname
   * @param string $date
   */
  public function __construct($xml_fname, $date) {
    $cpe = file($xml_fname);
    $this->total_cpes = count(preg_grep("/<cpe\-item/", $cpe));
    unset($cpe);

    parent::__construct($this, $xml_fname);
    $this->count = 0;
    $conn = new mysqli(DB_SERVER, "web", db::decrypt_pwd(), 'sagacity');
    $this->db = new db_helper($conn);
    $this->db->update("settings", ['meta_value' => new DateTime($date)], [
      [
        'field' => 'meta_key',
        'op'    => '=',
        'value' => 'cpe-load-date'
      ]
    ]);
    $this->db->execute();

    $this->db->select("software", ['cpe']);
    $cpes = $this->db->execute();
    if (!is_null($cpes) && is_array($cpes) && count($cpes)) {
      foreach ($cpes as $cpe) {
        if (isset($cpe['cpe'])) {
          $this->existing_cpes["{$cpe['cpe']}"] = 1;
        }
      }
    }

    if (!isset($this->existing_cpes["cpe:/o:generic:generic:-"])) {
      $this->new_cpes[] = [
        "cpe:/o:generic:generic:-",
        "cpe:2.3:o:generic:generic:*:*:*:*:*:*:*",
        "Generic Generic OS",
        "Generic"
      ];
    }

    if (!isset($this->existing_cpes["cpe:/a:generic:generic:-"])) {
      $this->new_cpes[] = [
        "cpe:/a:generic:generic:-",
        "cpe:2.3:a:generic:generic:*:*:*:*:*:*:*",
        "Generic Generic",
        "Generic"
      ];
    }
  }

  /**
   * Start function for &lt;cpe-list&gt;/&lt;cpe-item&gt; element
   *
   * @param array $attrs
   */
  public function cpe_list_cpe_item($attrs) {
    if (isset($attrs['deprecated']) && $attrs['deprecated'] == 'true') {
      $this->skip = true;

      if (isset($attrs['name'])) {
        $this->cpe = $attrs['name'];
      }

      return;
    }

    $match = [];
    if (isset($attrs['name'])) {
      $this->cpe = $attrs['name'];
      $this->cpe_arr = explode(':', $attrs['name']);
    }

    switch ($this->cpe_arr[2]) {
      case 'microsoft':
        $this->short_string = '';
        break;
      case 'redhat':
        $this->short_string = 'RH';
        break;
      case 'opensuse_project':
        $this->short_string = 'openSuSE';
        break;
      default:
        $this->short_string = ucfirst($this->cpe_arr[2]);
    }

    switch ($this->cpe_arr[3]) {
      case 'windows':
      case 'windows_nt':
        $this->short_string .= 'Win';
        break;
      case (preg_match("/windows_([\d\.]+)(_server)?$/", $this->cpe_arr[3], $match) ? true : false):
        if (isset($match[2]) && $match[2]) {
          $this->short_string .= "Win Server {$match[1]}";
        }
        else {
          $this->short_string .= "Win {$match[1]}";
        }
        break;
      case (preg_match("/windows_server_([\d]+)$/", $this->cpe_arr[3], $match) ? true : false):
        $this->short_string .= "Win Server {$match[1]}";
        break;
      case (preg_match("/windows_(vista|xp)$/", $this->cpe_arr[3], $match) ? true : false):
        $this->short_string .= "Win {$match[1]}";
        break;
      case 'pocket_ie':
      case 'pocket_internet_explorer':
      case 'internet_explorer':
      case 'ie':
        $this->short_string .= "IE";
        break;
      case 'enterprise_linux_server':
        $this->short_string .= " EL";
        break;
      case 'enterprise_linux_workstation':
        $this->short_string .= " EL";
        break;
      default:
        $this->short_string .= " " . ucfirst(str_replace(array('-', '_'), ' ', $this->cpe_arr[3]));
    }

    if (isset($this->cpe_arr[4]) && ($this->cpe_arr[4] != '-' || $this->cpe_arr[4] != '*')) {
      switch ($this->cpe_arr[4]) {
        case (preg_match("/([R\d\.z]+)/", $this->cpe_arr[4], $match) ? true : false):
          $this->short_string .= " {$match[1]}";
          break;
        default:
          $this->short_string .= " " . $this->cpe_arr[4];
      }
    }

    if (isset($this->cpe_arr[6]) && $this->cpe_arr[6]) {
      $this->short_string .= " " . str_replace('~', '', $this->cpe_arr[6]);
    }

    if (isset($this->cpe_arr[5]) && !empty($this->cpe_arr[5]) && $this->cpe_arr[5] != '-') {
      //die(print_r($this->cpe_arr, true));
      switch ($this->cpe_arr[5]) {
        case (preg_match("/sp([\d]+)/", $this->cpe_arr[5], $match) ? true : false):
          $this->short_string .= " SP{$match[1]}";
          break;
        default:
          $this->short_string .= " " . strtoupper($this->cpe_arr[5]);
      }
    }
  }

  /**
   * Start function for &lt;cpe-list&gt;/&lt;cpe-item&gt;/&lt;title&gt; element
   *
   * @param array $attrs
   *    Name/value pair of attributes
   */
  public function cpe_list_cpe_item_title($attrs) {
    if (isset($attrs['xml:lang']) && $attrs['xml:lang'] != 'en-US') {
      $this->skip = true;
    }
  }

  /**
   * Character data function for &lt;cpe-list&gt;/&lt;cpe-item&gt;/&lt;title&gt; element
   *
   * @param string $data
   *    The value within the tags
   */
  public function cpe_list_cpe_item_title_data($data) {
    $this->sw_string = trim($data);
  }

  /**
   * Start function for &lt;cpe-list&gt;/&lt;cpe-item&gt;/&lt;cpe-23:cpe23-item&gt; element
   *
   * @param array $attrs
   *    Name/value pairs of attributes
   */
  public function cpe_list_cpe_item_cpe_23_cpe23_item($attrs) {
    if (isset($attrs['name'])) {
      $this->cpe23 = $attrs['name'];
    }
  }

  /**
   * End function for &lt;cpe-list&gt;/&lt;cpe-item&gt; element
   */
  public function cpe_list_cpe_item_end() {
    // if we are supposed to skip this CPE (because of deprecation or the title is not english) then delete it from the database
    if ($this->skip) {
      $this->cpes_to_remove[] = $this->cpe;

      $this->skip = false;

      PHP_SAPI == "cli" ? print "-" : null;
    }
    // look for current item in the existing list
    elseif (!isset($this->existing_cpes["{$this->cpe}"])) {
      $this->new_cpes[] = [
        $this->cpe,
        $this->cpe23,
        $this->sw_string,
        $this->short_string
      ];

      PHP_SAPI == "cli" ? print "*" : null;
    }
    else { // current cpe is already in the database, so just print "."
      PHP_SAPI == 'cli' ? print "." : null;
    }

    $this->count++;

    // every 100 CPEs, print the count and execute the SQL.
    if ($this->count % 100 == 0) {
      print "\t$this->count completed" . PHP_EOL;
      $this->db->update("settings", ['meta_value' => number_format(($this->count / $this->total_cpes * 100), 2)], [
        [
          'field' => 'meta_key',
          'op'    => '=',
          'value' => 'cpe-progress'
        ]
      ]);
      $this->db->execute();

      if (is_array($this->new_cpes) && count($this->new_cpes)) {
        $this->db->extended_insert('software', ['cpe', 'cpe23', 'sw_string', 'short_sw_string'], $this->new_cpes, true);
        $this->new += $this->db->execute();

        unset($this->new_cpes);
        $this->{'new_cpes'} = [];
      }

      if (is_array($this->cpes_to_remove) && count($this->cpes_to_remove)) {
        $this->db->delete("software", null, [
          [
            'field' => 'cpe',
            'op'    => IN,
            'value' => $this->cpes_to_remove
          ]
        ]);
        $this->deleted += $this->db->execute();
        unset($this->cpes_to_remove);
        $this->{'cpes_to_remove'} = [];
      }
    }

    // reset cpe, cpe23, and sw_string for next cpe item
    $this->cpe = '';
    $this->cpe23 = '';
    $this->sw_string = '';
    $this->short_string = '';
  }

  /**
   * End function for &lt;cpe-list&gt; element
   */
  public function cpe_list_end() {
    // execute what is left in the SQL just incase there are some leftover
    if (is_array($this->new_cpes) && count($this->new_cpes)) {
      $this->db->extended_insert('software', ['cpe', 'cpe23', 'sw_string', 'short_sw_string'], $this->new_cpes, true);
      $this->db->execute();
    }

    if (is_array($this->cpes_to_remove) && count($this->cpes_to_remove)) {
      $this->db->delete("software", null, [
        [
          'field' => 'cpe',
          'op'    => IN,
          'value' => $this->cpes_to_remove
        ]
      ]);
      $this->deleted += $this->db->execute();
    }

    $this->db->update("settings", ['meta_value' => 100], [
      [
        'field' => 'meta_key',
        'op'    => IN,
        'value' => ['cpe-dl-progress', 'cpe-progress']
      ]
    ]);
    $this->db->execute();
  }

}

$xml = new cpe_parser($cmd['f'], $cmd['d']);
$xml->debug = false;
if (isset($cmd['debug'])) {
  $xml->debug = true;
}
elseif (LOG_LEVEL == E_DEBUG) {
  $xml->debug = true;
}
//Enter xml code here
$xml->parse();

$unchanged = $xml->count - $xml->new - $xml->deleted;

print <<<EOO

Unchanged CPEs: $unchanged
New CPEs: $xml->new
Deleted CPEs: $xml->deleted
EOO;

function usage() {
  print <<<EOO
Purpose: To parse the NIST CPE list

Output: You will see either a . (dot), * (asterisk), or - (hyphen) for each CPE.
  .  - CPE was already in the DB
  *  - CPE was added to the DB
  -  - CPE was removed from the DB (CPE deprecated)

Usage: php parse_cpe.php -f={CPE list file} [--debug] [--help]

 -f={CPE file}      The CPE file to parse retrieved from http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml

 --debug            Debugging output
 --help             This screen

EOO;
}
