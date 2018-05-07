<?php
/**
 * File: chart.php
 * Author: Ryan Prather
 * Purpose: {purpose of file}
 * Created: Nov 13, 2014
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Nov 13, 2014 - File created
 */

include_once 'pChart/class/pBubble.class.php';
include_once 'pChart/class/pCache.class.php';
include_once 'pChart/class/pData.class.php';
include_once 'pChart/class/pDraw.class.php';
include_once 'pChart/class/pImage.class.php';
include_once 'pChart/class/pIndicator.class.php';
include_once 'pChart/class/pPie.class.php';
include_once 'pChart/class/pRadar.class.php';
include_once 'pChart/class/pScatter.class.php';
include_once 'pChart/class/pSplit.class.php';

if (!extension_loaded('gd') && !extension_loaded('gd2')) {
  die("GD extensions not loaded");
}

$chart = new pData();
$chart->addPoints(array(0,3.5,4,3,5));

$pic = new pImage(700, 250, $chart);

$pic->setGraphArea(60, 40, 670, 190);

$pic->setFontProperties(array("FontName"=>"pChart/fonts/verdana.ttf","FontSize"=>11));

$pic->drawScale();

$pic->drawLineChart();

$pic->stroke();
