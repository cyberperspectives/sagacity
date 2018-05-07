<?php

/**
 * File: excelConditionalStyles.inc
 * Author: Ryan Prather
 * Purpose: The purpose of this file is hold any constants or variables that will be used in creating an eChecklist for export
 * Created: 6 Jan 2014
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
 *  - Jan 6, 2014 - File created
 *  - Mar 10, 2017 - Formatting, added Cyber Perspectives copyright, and added $light_gray variable color
 *  - May 13, 2017 - Updated to use new PHPSpreadsheet library
 *  - Dec 27, 2017 - Syntax updates
 */
$conditions = array(
  'unclass_classification' => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'fouo_classification'    => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'secret_classification'  => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'exception'              => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'false_positive'         => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'nf_na_conflict'         => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'open_conflict'          => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'open_cat_1_count'       => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'open_cat_2_count'       => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'open_cat_3_count'       => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'not_a_finding'          => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'true'                   => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'not_applicable'         => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'not_reviewed'           => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'no_data'                => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'open'                   => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'false'                  => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'cat_1'                  => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'cat_2'                  => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'cat_3'                  => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'not_a_finding_count'    => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'not_applicable_count'   => new \PhpOffice\PhpSpreadsheet\Style\Conditional(),
  'not_reviewed_count'     => new \PhpOffice\PhpSpreadsheet\Style\Conditional()
);

$styles = array(
  'header'      => array(
    'bold' => true
  ),
  'right'       => array(
    'horizontal' => \PhpOffice\PhpSpreadsheet\Style\Alignment::HORIZONTAL_RIGHT
  ),
  'yellow_fill' => array(
    'fill' => array(
      'type'       => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
      'startcolor' => array(
        'rgb' => 'FFFF00'
      )
    )
  )
);

$validation = array(
  'host_status' => new \PhpOffice\PhpSpreadsheet\Cell\DataValidation(),
  'true_false'  => new \PhpOffice\PhpSpreadsheet\Cell\DataValidation()
);

$red = new \PhpOffice\PhpSpreadsheet\Style\Color();
$red->setARGB('FFFF0000');

$green = new \PhpOffice\PhpSpreadsheet\Style\Color();
$green->setARGB('FF92D050');

$light_blue = new \PhpOffice\PhpSpreadsheet\Style\Color();
$light_blue->setARGB('FFC5D9F1');

$yellow = new \PhpOffice\PhpSpreadsheet\Style\Color();
$yellow->setARGB('FFFFFF00');

$light_yellow = new \PhpOffice\PhpSpreadsheet\Style\Color();
$light_yellow->setARGB('FFFFFF66');

$orange = new \PhpOffice\PhpSpreadsheet\Style\Color();
$orange->setARGB('FFFFC000');

$black = new \PhpOffice\PhpSpreadsheet\Style\Color();
$black->setARGB('00000000');

$white = new \PhpOffice\PhpSpreadsheet\Style\Color();
$white->setARGB('FFFFFFFF');

$light_brown = new \PhpOffice\PhpSpreadsheet\Style\Color();
$light_brown->setRGB('DDD9C4');

$light_gray = new \PhpOffice\PhpSpreadsheet\Style\Color();
$light_gray->setRGB('D6D4CA');

$conditions['unclass_classification']->setConditionType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['unclass_classification']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['unclass_classification']->setText('UNCLASSIFIED');
$conditions['unclass_classification']->getStyle()
    ->getFont()
    ->setColor($green)
    ->setBold(true);

$conditions['fouo_classification']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['fouo_classification']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['fouo_classification']->setText('UNCLASSIFIED//FOUO');
$conditions['fouo_classification']->getStyle()
    ->getFont()
    ->setColor($orange)
    ->setBold(true);

$conditions['secret_classification']->setConditionType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['secret_classification']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['secret_classification']->setText('SECRET');
$conditions['secret_classification']->getStyle()
    ->getFont()
    ->setColor($red)
    ->setBold(true);

$conditions['open']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['open']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['open']->setText('Open');
$conditions['open']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['open']->getStyle()
    ->getFill()
    ->setEndColor($red);
$conditions['open']->getStyle()
    ->getFont()
    ->setColor($white);
$conditions['false']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['false']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['false']->setText('FALSE');
$conditions['false']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['false']->getStyle()
    ->getFill()
    ->setEndColor($red);

$conditions['exception']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['exception']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['exception']->setText('Exception');
$conditions['exception']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['exception']->getStyle()
    ->getFill()
    ->setEndColor($red);
$conditions['exception']->getStyle()
    ->getFont()
    ->setColor($white);

$conditions['cat_1']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CELLIS);
$conditions['cat_1']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_EQUAL);
$conditions['cat_1']->addCondition('"I"');
$conditions['cat_1']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['cat_1']->getStyle()
    ->getFill()
    ->setEndColor($red);
$conditions['cat_1']->getStyle()
    ->getFont()
    ->setColor($white);

$conditions['cat_2']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CELLIS);
$conditions['cat_2']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_EQUAL);
$conditions['cat_2']->addCondition('"II"');
$conditions['cat_2']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['cat_2']->getStyle()
    ->getFill()
    ->setEndColor($light_yellow);

$conditions['cat_3']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CELLIS);
$conditions['cat_3']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_EQUAL);
$conditions['cat_3']->addCondition('"III"');
$conditions['cat_3']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['cat_3']->getStyle()
    ->getFill()
    ->setEndColor($orange);

$conditions['no_data']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['no_data']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['no_data']->setText('No Data');
$conditions['no_data']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['no_data']->getStyle()
    ->getFill()
    ->setEndColor($black);
$conditions['no_data']->getStyle()
    ->getFont()
    ->setColor($white);

$conditions['nf_na_conflict']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['nf_na_conflict']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['nf_na_conflict']->setText('NF/NA CONFLICT:');
$conditions['nf_na_conflict']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['nf_na_conflict']->getStyle()
    ->getFill()
    ->setEndColor($light_blue);

$conditions['open_conflict']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['open_conflict']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['open_conflict']->setText('OPEN CONFLICT:');
$conditions['open_conflict']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['open_conflict']->getStyle()
    ->getFill()
    ->setEndColor($red);
$conditions['open_conflict']->getStyle()
    ->getFont()
    ->setColor($white);

$conditions['not_a_finding']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['not_a_finding']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['not_a_finding']->setText('Not a Finding');
$conditions['not_a_finding']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['not_a_finding']->getStyle()
    ->getFill()
    ->setEndColor($green);
$conditions['true']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['true']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['true']->setText('TRUE');
$conditions['true']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['true']->getStyle()
    ->getFill()
    ->setEndColor($green);

$conditions['false_positive']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['false_positive']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['false_positive']->setText('False Positive');
$conditions['false_positive']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['false_positive']->getStyle()
    ->getFill()
    ->setEndColor($green);

$conditions['not_applicable']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['not_applicable']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['not_applicable']->setText('Not Applicable');
$conditions['not_applicable']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['not_applicable']->getStyle()
    ->getFill()
    ->setEndColor($light_blue);

$conditions['not_reviewed']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_CONTAINSTEXT);
$conditions['not_reviewed']->setOperatorType(\PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_CONTAINSTEXT);
$conditions['not_reviewed']->setText('Not Reviewed');
$conditions['not_reviewed']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['not_reviewed']->getStyle()
    ->getFill()
    ->setEndColor($yellow);

$conditions['open_cat_1_count']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_EXPRESSION);
$conditions['open_cat_1_count']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_GREATERTHANOREQUAL);
$conditions['open_cat_1_count']->setText('1');
$conditions['open_cat_1_count']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['open_cat_1_count']->getStyle()
    ->getFill()
    ->setEndColor($red);
$conditions['open_cat_1_count']->getStyle()
    ->getFont()
    ->setColor($white);

$conditions['open_cat_2_count']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_EXPRESSION);
$conditions['open_cat_2_count']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_GREATERTHANOREQUAL);
$conditions['open_cat_2_count']->setText('1');
$conditions['open_cat_2_count']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['open_cat_2_count']->getStyle()
    ->getFill()
    ->setEndColor($yellow);

$conditions['open_cat_3_count']->setConditionType(\PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_EXPRESSION);
$conditions['open_cat_3_count']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_GREATERTHANOREQUAL);
$conditions['open_cat_3_count']->setText('1');
$conditions['open_cat_3_count']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['open_cat_3_count']->getStyle()
    ->getFill()
    ->setEndColor($orange);

$conditions['not_a_finding_count']->setConditionType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_EXPRESSION);
$conditions['not_a_finding_count']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_GREATERTHANOREQUAL);
$conditions['not_a_finding_count']->setText('1');
$conditions['not_a_finding_count']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['not_a_finding_count']->getStyle()
    ->getFill()
    ->setEndColor($green);

$conditions['not_applicable_count']->setConditionType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_EXPRESSION);
$conditions['not_applicable_count']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_GREATERTHANOREQUAL);
$conditions['not_applicable_count']->setText('1');
$conditions['not_applicable_count']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['not_applicable_count']->getStyle()
    ->getFill()
    ->setEndColor($light_blue);

$conditions['not_reviewed_count']->setConditionType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::CONDITION_EXPRESSION);
$conditions['not_reviewed_count']->setOperatorType(
    \PhpOffice\PhpSpreadsheet\Style\Conditional::OPERATOR_GREATERTHANOREQUAL);
$conditions['not_reviewed_count']->setText('1');
$conditions['not_reviewed_count']->getStyle()
    ->getFill()
    ->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID);
$conditions['not_reviewed_count']->getStyle()
    ->getFill()
    ->setEndColor($yellow);

$validation['host_status']->setType(\PhpOffice\PhpSpreadsheet\Cell\DataValidation::TYPE_LIST);
$validation['host_status']->setFormula1("=ValidStatus");
$validation['host_status']->setShowDropDown(true);

$validation['true_false']->setType(\PhpOffice\PhpSpreadsheet\Cell\DataValidation::TYPE_LIST);
$validation['true_false']->setFormula1("=TRUE,FALSE");
$validation['true_false']->setShowDropDown(true);

/**
 * Add borders to cells
 */
$borders = [
  'borders' => [
    'allborders' => [
      'style' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN,
      'color' => [
        'rgb' => '000000'
      ]
    ]
  ]
];
