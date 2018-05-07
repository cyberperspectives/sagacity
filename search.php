<?php

/**
 * File: search.php
 * Author: Ryan Prather <ryan.prather@cyberperspectives.com>
 * Purpose: Contain all search/filtering functionality within Sagacity
 * Created: May 24, 2017
 *
 * Copyright 2017: Cyber Perspective, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - May 24, 2017 - File created
 *  - May 26, 2017 - Couple bug fixes
 *  - Jul 13, 2017 - Fixed a couple minor display bugs
 *  - Dec 27, 2017 - Syntax updates
 */
include_once 'config.inc';
include_once 'helper.inc';
include_once 'database.inc';

$db = new db();

$type = filter_input(INPUT_POST, 'type', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$q = filter_input(INPUT_POST, 'q', FILTER_SANITIZE_STRING, FILTER_NULL_ON_FAILURE);
$start = filter_input(INPUT_POST, 'start', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$len = filter_input(INPUT_POST, 'length', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$draw = filter_input(INPUT_POST, 'draw', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);
$filter = filter_input(INPUT_POST, 'search', FILTER_SANITIZE_STRING, FILTER_REQUIRE_ARRAY);

$where = [];
$op = '=';
$field = null;
$ret = null;

if (empty($q)) {
  print header(JSON) . json_encode(null);
  die;
}

if (strpos($q, "%") !== false) {
  $op = LIKE;
  $q = "'$q'";
}

if ($type == 'stig' || $type == 'vms' || $type == 'ia' || $type == 'nessus') {
  if ($type == 'stig') {
    $field = '`STIG_ID`';
  }
  elseif ($type == 'vms') {
    $field = '`VMS_ID`';
  }
  elseif ($type == 'ia') {
    $field = '`IA_Controls`';
  }
  elseif ($type == 'nessus') {
    $field = '`Nessus_ID`';
  }

  if (!is_null($field)) {
    $where[] = [
      'field' => $field,
      'op'    => $op,
      'value' => $q
    ];
  }

  if (!empty($filter['value'])) {
    $where[] = [
      'field'      => 'pdi.STIG_ID',
      'op'         => LIKE,
      'value'      => "'%{$filter['value']}%'",
      'open-paren' => true,
      'sql_op'     => 'AND'
    ];
    $where[] = [
      'field'  => 'pdi.VMS_ID',
      'op'     => LIKE,
      'value'  => "'%{$filter['value']}%'",
      'sql_op' => 'OR'
    ];
    $where[] = [
      'field'  => 'pdi.IA_Controls',
      'op'     => LIKE,
      'value'  => "'%{$filter['value']}%'",
      'sql_op' => 'OR'
    ];
    $where[] = [
      'field'  => 'pdi.Short_Title',
      'op'     => LIKE,
      'value'  => "'%{$filter['value']}%'",
      'sql_op' => 'OR'
    ];
    $where[] = [
      'field'  => 'pdi.Description',
      'op'     => LIKE,
      'value'  => "'%{$filter['value']}%'",
      'sql_op' => 'OR'
    ];
    $where[] = [
      'field'       => 'lu.check_contents',
      'op'          => LIKE,
      'value'       => "'%{$filter['value']}%'",
      'sql_op'      => 'OR',
      'close-paren' => true
    ];
  }

  $db->help->select_count("sagacity.pdi", $where, [
    'table_joins' => [
      "LEFT JOIN sagacity.pdi_checklist_lookup lu ON pdi.pdi_id = lu.pdi_id",
      "LEFT JOIN sagacity.checklist chk ON chk.id = lu.checklist_id"
    ]
  ]);
  $count = $db->help->execute();

  $ret = [
    'columns'         => [
      ['title' => 'STIG ID', 'data' => 'stig_id'],
      ['title' => 'VMS ID', 'data' => 'vms_id'],
      ['title' => 'Checklist Name', 'data' => 'name'],
      ['title' => 'Type', 'data' => 'type'],
      ['title' => 'PDI', 'data' => 'pdi_id'],
      ['title' => 'File Name', 'data' => 'file']
    ],
    'draw'            => $draw,
    'recordsTotal'    => $count,
    'recordsFiltered' => $count,
    'data'            => []
  ];

  $db->help->select("sagacity.pdi", null, $where, [
    'table_joins' => [
      "LEFT JOIN sagacity.pdi_checklist_lookup lu ON pdi.pdi_id = lu.pdi_id",
      "LEFT JOIN sagacity.checklist chk ON chk.id = lu.checklist_id"
    ],
    'limit'       => $len,
    'start'       => $start
  ]);
  //error_log($db->help->sql);
  $rows = $db->help->execute();
  if (is_array($rows) && count($rows) && isset($rows['STIG_ID'])) {
    $rows = [0 => $rows];
  }

  if (is_array($rows) && count($rows) && isset($rows[0])) {
    foreach ($rows as $row) {
      $ret['data'][] = [
        'stig_id' => $row['STIG_ID'],
        'vms_id'  => $row['VMS_ID'],
        'name'    => $row['name'],
        'type'    => $row['type'],
        'pdi_id'  => $row['pdi_id'],
        'file'    => $row['file_name']
      ];
    }
  }
}
elseif ($type == 'cve') {
  $where[] = [
    'field' => 'db.cve_id',
    'op'    => $op,
    'value' => $q
  ];

  if (!empty($filter['value'])) {
    $where[] = [
      'field'      => 'status',
      'op'         => LIKE,
      'value'      => "'%{$filter['value']}%'",
      'sql_op'     => 'AND',
      'open-paren' => true
    ];
    $where[] = [
      'field'       => 'desc',
      'op'          => LIKE,
      'value'       => "'%{$filter['value']}%'",
      'sql_op'      => 'OR',
      'close-paren' => true
    ];
  }

  $db->help->select_count("sagacity.cve_db db", $where, [
    'table_joins' => [
      "LEFT JOIN sagacity.cve ON db.cve_id = cve.cve_id"
    ]
  ]);
  $count = $db->help->execute();

  $ret = [
    'columns'         => [
      ['title' => 'PDI ID', 'data' => 'pdi_id'],
      ['title' => 'CVE ID', 'data' => 'cve_id'],
      ['title' => 'Description', 'data' => 'desc'],
      ['title' => 'Status', 'data' => 'status'],
      ['title' => 'References', 'data' => 'ref']
    ],
    'draw'            => $draw,
    'recordsTotal'    => $count,
    'recordsFiltered' => $count,
    'data'            => []
  ];

  $db->help->select("sagacity.cve_db db", ['db.cve_id', 'cve.pdi_id', 'db.seq', 'db.status', 'db.desc'], $where, [
    'table_joins' => [
      "LEFT JOIN sagacity.cve ON db.cve_id = cve.cve_id"
    ],
    'limit'       => $len,
    'start'       => $start
  ]);
  $rows = $db->help->execute();
  if (is_array($rows) && count($rows) && isset($rows['cve_id'])) {
    $rows = [0 => $rows];
  }

  if (is_array($rows) && count($rows) && isset($rows[0])) {
    foreach ($rows as $row) {
      $references = null;
      $db->help->select("sagacity.cve_references", ['source', 'url'], [
        [
          'field' => 'cve_seq',
          'op'    => '=',
          'value' => $row['cve_id']
        ],
        [
          'field'  => 'url',
          'op'     => '!=',
          'value'  => '',
          'sql_op' => 'AND'
        ]
          ], [
        'group' => 'source'
      ]);

      $refs = $db->help->execute();
      if (is_array($refs) && count($refs) && isset($refs['source'])) {
        $refs = [0 => $refs];
      }

      if (is_array($refs) && count($refs) && isset($refs[0])) {
        foreach ($refs as $ref) {
          $references .= "<a href='{$ref['url']}' target='_blank'>{$ref['source']}</a> ";
        }
      }

      $ret['data'][] = [
        'pdi_id' => "<a href='#' onclick='javascript:open_pdi(\"{$row['pdi_id']}\");'>{$row['pdi_id']}</a>",
        'cve_id' => $row['cve_id'],
        'desc'   => $row['desc'],
        'status' => $row['status'],
        'ref'    => $references
      ];
    }
  }
}
elseif ($type == 'cpe') {
  $where[] = [
    'field' => 'cpe',
    'op'    => $op,
    'value' => $q
  ];

  if (!empty($filter['search'])) {
    $where[] = [
      'field'  => 'cpe',
      'op'     => LIKE,
      'value'  => $filter['search'],
      'sql_op' => 'OR'
    ];
  }

  $db->help->select_count("sagacity.software", $where);
  $count = $db->help->execute();

  $ret = [
    'columns'         => [
      ['title' => 'Man', 'data' => 'man'],
      ['title' => 'Name', 'data' => 'name'],
      ['title' => 'Ver', 'data' => 'ver'],
      ['title' => 'CPE', 'data' => 'cpe'],
      ['title' => 'String', 'data' => 'sw_string']
    ],
    'draw'            => $draw,
    'recordsTotal'    => $count,
    'recordsFiltered' => $count,
    'data'            => []
  ];

  $db->help->select("sagacity.software", null, $where);
  $rows = $db->help->execute();

  if (is_array($rows) && count($rows) && isset($rows['cpe'])) {
    $rows = [0 => $rows];
  }

  if (is_array($rows) && count($rows) && isset($rows[0])) {
    foreach ($rows as $row) {
      list($cpe, $type, $man, $name, $ver) = explode(":", $row['cpe']);
      $ret['data'][] = [
        'man'       => ucwords($man),
        'name'      => ucwords($name),
        'ver'       => $ver,
        'cpe'       => $row['cpe'],
        'sw_string' => $row['sw_string']
      ];
    }
  }
}
elseif ($type == 'iavm') {
  $where[] = [
    'field' => 'iavmNoticeNumber',
    'op'    => $op,
    'value' => $q
  ];

  $db->help->select_count("sagacity.iavm_notices", $where);
  $count = $db->help->execute();

  $ret = [
    'columns'         => [
      ['title' => 'PDI ID', 'data' => 'pdi_id'],
      ['title' => 'IAVM Notice', 'data' => 'iavm'],
      ['title' => 'Title', 'data' => 'title'],
      ['title' => 'Category', 'data' => 'cat'],
      ['title' => 'Link', 'data' => 'link']
    ],
    'draw'            => $draw,
    'recordsTotal'    => $count,
    'recordsFiltered' => $count,
    'data'            => []
  ];

  $db->help->select("sagacity.iavm_notices", null, $where, [
    'order' => 'iavmNoticeNumber'
  ]);
  $rows = $db->help->execute();

  if (is_array($rows) && count($rows) && isset($rows['iavmNoticeNumber'])) {
    $rows = [0 => $rows];
  }

  if (is_array($rows) && count($rows) && isset($rows[0])) {
    foreach ($rows as $row) {
      $cat = implode("", array_fill(0, $row['stigFindingSeverity'], "I"));
      $ret['data'][] = [
        'pdi_id' => "<a href='#' onclick='javascript:open_pdi(\"{$row['pdi_id']}\");'>{$row['pdi_id']}</a>",
        'iavm'   => $row['iavmNoticeNumber'],
        'title'  => $row['title'],
        'cat'    => $cat,
        'link'   => "<a href='/reference/iavms/{$row['file_name']}' target='_blank'>XML</a>"
      ];
    }
  }
}
else {
  $where = [
    [
      'field' => 'pdi.short_title',
      'op'    => LIKE,
      'value' => $q
    ],
    [
      'field'  => 'pdi.description',
      'op'     => LIKE,
      'value'  => $q,
      'sql_op' => 'OR'
    ],
    [
      'field'  => 'pdi.check_content',
      'op'     => LIKE,
      'value'  => $q,
      'sql_op' => 'OR'
    ]
  ];

  if (!empty($filter['value'])) {
    $where[] = [
      'field'      => 's.stig_id',
      'op'         => LIKE,
      'value'      => "'%{$filter['value']}%'",
      'sql_op'     => 'AND',
      'open-paren' => true
    ];
    $where[] = [
      'field'       => 'gd.vms_id',
      'op'          => LIKE,
      'value'       => "'%{$filter['value']}%'",
      'sql_op'      => 'OR',
      'close-paren' => true
    ];
  }

  $db->help->select_count("sagacity.pdi_catalog pdi", $where, [
    'table_joins' => [
      "LEFT JOIN sagacity.stigs s ON s.pdi_id=pdi.id",
      "LEFT JOIN sagacity.golddisk gd ON gd.pdi_id=pdi.id",
      "LEFT JOIN sagacity.pdi_checklist_lookup pcl ON pdi.id=pcl.pdi_id",
      "LEFT JOIN sagacity.checklist c ON c.id=pcl.checklist_id"
    ]
  ]);
  $count = $db->help->execute();

  $ret = [
    'columns'         => [
      ['title' => 'STIG ID', 'data' => 'stig_id'],
      ['title' => 'VMS ID', 'data' => 'vms_id'],
      ['title' => 'Checklist Name', 'data' => 'name'],
      ['title' => 'Type', 'data' => 'type'],
      ['title' => 'PDI', 'data' => 'pdi_id'],
      ['title' => 'File Name', 'data' => 'file']
    ],
    'draw'            => $draw,
    'recordsTotal'    => $count,
    'recordsFiltered' => $count,
    'data'            => []
  ];

  $db->help->select("sagacity.pdi_catalog pdi", [
    "pdi.id AS 'pdi_id'", "pdi.short_title AS 'Short_Title'", "pdi.description AS 'Description'",
    "s.stig_id AS 'STIG_ID'", "gd.vms_id AS 'VMS_ID'",
    "c.id AS 'chk_id'", "c.`name` AS 'chk_name'", "c.file_name", "c.`type`", "c.`release`", "c.`ver`"
      ], $where, [
    'table_joins' => [
      "LEFT JOIN sagacity.stigs s ON s.pdi_id=pdi.id",
      "LEFT JOIN sagacity.golddisk gd ON gd.pdi_id=pdi.id",
      "LEFT JOIN sagacity.pdi_checklist_lookup pcl ON pdi.id=pcl.pdi_id",
      "LEFT JOIN sagacity.checklist c ON c.id=pcl.checklist_id"
    ],
    'start'       => $start,
    'limit'       => $len
  ]);

  $rows = $db->help->execute();
  if (is_array($rows) && count($rows) && isset($rows['pdi_id'])) {
    $rows = [0 => $rows];
  }

  if (is_array($rows) && count($rows) && isset($rows[0])) {
    foreach ($rows as $row) {
      $name = str_replace("Security Technical Implementation Guide", "STIG", $row['chk_name']);
      $title = "{$row['Short_Title']} (<span style = 'font-style:italic;'>from $name</span>)";
      $desc = $row['Description'];

      $file_name = basename($row['file_name']);

      $ret['data'][] = [
        'stig_id' => $row['STIG_ID'],
        'vms_id'  => $row['VMS_ID'],
        'name'    => "{$row['chk_name']} V{$row['ver']}R{$row['release']}",
        'type'    => $row['type'],
        'pdi_id'  => "<a href='#' onclick='javascript:open_stig(\"$file_name\", \"{$row['VMS_ID']}\");'>PDI</a>",
        'file'    => "<a href='/reference/stigs/$file_name' target='_blank'><img src='/img/file.png' style='width:25px;' title='$file_name' /></a>"
      ];
    }
  }
}

print header(JSON) . json_encode($ret);
