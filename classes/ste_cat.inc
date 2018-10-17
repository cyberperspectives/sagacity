<?php
/**
 * File: ste_cat.inc
 * Author: Ryan Prather
 * Purpose: Represents a category that is assigned to an ST&E
 * Created: Sep 16, 2013
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 16, 2013 - File created
 *  - Sep 1, 2016 - Updated Copyright, added category editing,
 * 					Added functionality for expected sources in this category,
 * 					Converted category row to use div tags,
 * 					Added vertical menu to accessing other functionality
 * - Nov 21, 2016 - Added exclusion for Unassigned category so that the export button is not displayed
 * - Dec 7, 2016 - Disabled eChecklist export on Unassigned category
 * - Jan 30, 2017 - Removed eChecklist export for the Unassigned category and added autocategorization for Unassigned category
 * - Feb 15, 2017 - Added Export CKL link in vertical menu.  Need to add functionality to do that.
 * - Feb 21, 2017 - Removed above Export CKL link in favor of writing a command script
 * - Apr 5, 2017 - Removed "Rename Cat" vertical menu item, formatting, and expanded functionality of the add_Sources method
 * - Apr 7, 2017 - Removed vertical menu for "Unassigned" category
 * - Apr 11, 2017 - Make "Add target" open in new tab
 * - May 13, 2017 - Added "Export CKL" to category header dropdown
 * - Jan 10, 2018 - Formatting, added getSTECatRow method for /ste/stats.php and getSourceIDs method
 */

/**
 * Represents the ST&E categories
 *
 * @author Ryan Prather
 */
class ste_cat
{

    /**
     * category ID
     *
     * @var integer
     */
    protected $id = 0;

    /**
     * STE ID
     *
     * @var integer
     */
    protected $ste_id = 0;

    /**
     * category name
     *
     * @var string
     */
    protected $name = '';

    /**
     * Analyst in charge of category
     *
     * @var string
     */
    protected $analyst = '';

    /**
     * Array of sources that are expected in the category
     *
     * @var array:sources
     */
    protected $sources = [];

    /**
     * Variable to store count of Open findings in all targets in this category
     *
     * @var integer
     */
    public $open = 0;

    /**
     * Variable to store count of Not a Finding findings in all targets in this category
     *
     * @var integer
     */
    public $nf = 0;

    /**
     * Variable to store count of Not Reviewed findings in all targets in this category
     *
     * @var integer
     */
    public $nr = 0;

    /**
     * Variable to store count of Not Applicable findings in all targets in this category
     *
     * @var integer
     */
    public $na = 0;

    /**
     * Variable to store total number of PDIs
     *
     * @var integer
     */
    public $total = 0;

    /**
     * Variable to store target count
     *
     * @var integer
     */
    public $tgt_count = 0;

    /**
     * Constructor
     *
     * @param integer $int_ID
     * @param integer $int_STE_ID
     * @param string $str_Name
     * @param string $str_Analyst
     */
    public function __construct($int_ID, $int_STE_ID, $str_Name, $str_Analyst)
    {
        $this->id      = $int_ID;
        $this->ste_id  = $int_STE_ID;
        $this->name    = $str_Name;
        $this->analyst = $str_Analyst;
    }

    /**
     * Getter function for ID
     *
     * @return integer
     */
    public function get_ID()
    {
        return $this->id;
    }

    /**
     * Setter function for ID
     *
     * @param integer $id_in
     */
    public function set_ID($id_in)
    {
        $this->id = $id_in;
    }

    /**
     * Getter function for STE ID
     *
     * @return integer
     */
    public function get_STE_ID()
    {
        return $this->ste_id;
    }

    /**
     * Getter function for name
     *
     * @return string
     */
    public function get_Name()
    {
        return $this->name;
    }

    /**
     * Getter function for analyst
     *
     * @return string
     */
    public function get_Analyst()
    {
        return $this->analyst;
    }

    /**
     * Getter function for the expected scan source array
     *
     * @return array:source
     */
    public function get_Sources()
    {
        return $this->sources;
    }

    /**
     * Getter function to return array of source IDs
     *
     * @return array:integer
     */
    public function getSourceIDs()
    {
        $ret = [];
        if (is_array($this->sources) && count($this->sources)) {
            foreach ($this->sources as $s) {
                $ret[] = $s->get_ID();
            }
        }

        return $ret;
    }

    /**
     * Function to add an expected scan source to the category
     * @param source $src
     */
    public function add_Source($src)
    {
        if (is_array($src) && count($src) && isset($src[0]) && is_a($src[0], 'source')) {
            $this->sources[$src[0]->get_ID()] = $src[0];
        }
        elseif (is_a($src, 'source')) {
            $this->sources[$src->get_ID()] = $src;
        }
    }

    /**
     * Function to remove an expected scan source from the category
     *
     * @param source $src
     */
    public function remove_Source($src)
    {
        unset($this->sources[$src->get_ID()]);
    }

    /**
     * Getter function for preformated option tag
     *
     * @return string
     */
    public function get_Option()
    {
        return "<option value='" . $this->id . "'>" . $this->name . "</option>";
    }

    /**
     * Getter function for preformated table row
     *
     * @param integer$intCount
     * @param mixed$status_count
     *
     * @return string
     */
    public function get_Table_Row($intCount = 0, $status_count = null)
    {
        $nf   = $this->nf;
        $open = $this->open;
        $na   = $this->na;
        if (!is_null($status_count) && is_array($status_count)) {
            if (isset($status_count['nf'])) {
                $nf = $status_count['nf'];
            }

            if (isset($status_count['na'])) {
                $na = $status_count['na'];
            }

            if (isset($status_count['open'])) {
                $open = $status_count['open'];
            }
        }

        if(!$intCount) {
            $intCount = $this->tgt_count;
        }

        $cat_sources = [];
        if (is_array($this->sources) && count($this->sources)) {
            foreach ($this->sources as $src) {
                $cat_sources[] = $src->get_ID();
            }
        }

        $sources   = json_encode($cat_sources);
        $link      = ($this->name != 'Unassigned' ? "<a href='javascript:void(0);' onclick='open_echecklist({$this->id});'>{$this->name}</a>" : $this->name);
        $analyst   = ($this->analyst ? "&nbsp;&nbsp;({$this->analyst})" : "");
        $export    = ($this->name != 'Unassigned' ?
            "<a href='/ste/export.php?cat={$this->id}' target='_new'>" .
            "<img src='/img/export.jpg' class='cat_icons' title='Export eChecklist' />" .
            "</a>" :
            "<img src='/img/move.jpg' class='cat_icons' title='Autocategorize targets' onclick='javascript:auto_cat();' />"
            );
        $vert_menu = ($this->name != 'Unassigned' ? $this->get_Vert_Option_Menu() : '');

        return <<<EOC
<div class='table-cat' id='cat_{$this->id}'>
    <input type='hidden' id='cat_{$this->id}_dl' value='0' />
    <input type='hidden' id='cat_sources_{$this->id}' value='{$sources}' />
    <span class='cat-cell' style='width:200px;'>
        <span class='cat-cell' style=''>
            <i class='far toggler fa-plus-square' id='collapse_{$this->id}' data-id='{$this->id}' title='Expand/Collapse All'></i>
        </span>
        <span class='cat-cell' style=''>
            <img src='/img/select_all.png' class='cat_icons' title='Select All/None' onclick='javascript:select("{$this->id}");' />
        </span>
        <span class='nf cat-cell' style='min-width:25px;' title='Not a Finding'>{$nf}</span>
        <span class='open cat-cell' style='min-width:25px;' title='Open'>{$open}</span>
        <span class='na cat-cell' style='min-width:25px;' title='Not Applicable'>{$na}</span>
    </span>
    <span class='cat-cell' style='width:800px;' id='cat_name_{$this->id}'>
        {$link} ({$intCount}){$analyst}
    </span>
    <span class='cat-cell' style='width:200px;'>
        <span class='cat-cell' style=''>
            $export
        </span>
        <span class='cat-cell' style=''>
            <form method='post' style='display: inline;' action='index.php' id='assign_{$this->id}'>
                <input type='hidden' name='action' value='assign' />
                <input type='hidden' name='ste' value='{$this->ste_id}' />
                <input type='hidden' name='cat_id' value='{$this->id}' />
                <input type='hidden' name='analyst' id='analyst_{$this->id}' value='' />
                <img src='/img/assign-to.png' class='cat_icons' title='Assign category to analyst' onclick='assign("{$this->id}");' />
            </form>
        </span>
        $vert_menu
    </span>
</div>

EOC;
    }

    /**
     * Getter function for preformated table row
     *
     * @param mixed $status_count
     *
     * @return string
     */
    public function getStatsCategoryRow($status_count = null)
    {
        $nf   = "0%";
        $nr   = "0%";
        $na   = "0%";
        $open = "0%";
        if (!is_null($status_count)) {
            if (isset($status_count['nf'])) {
                $nf = number_format(($status_count['nf'] / $this->total) * 100, 0) . "%";
            }

            if (isset($status_count['na'])) {
                $na = number_format(($status_count['na'] / $this->total) * 100, 0) . "%";
            }

            if (isset($status_count['open'])) {
                $open = number_format(($status_count['open'] / $this->total) * 100, 0) . "%";
            }

            if (isset($status_count['nr'])) {
                $nr = number_format(($status_count['nr'] / $this->total) * 100, 0) . "%";
            }
        }
        else {
            if ($this->total - $this->nr > 0) {
                $nf   = ($this->total ? number_format(($this->nf / ($this->total - $this->nr)) * 100, 0) . "%" : "0%");
                $na   = ($this->total ? number_format(($this->na / ($this->total - $this->nr)) * 100, 0) . "%" : "0%");
                $open = ($this->total ? number_format(($this->open / ($this->total - $this->nr) * 100), 0) . "%" : "0%");
            }
            $nr = ($this->total ? number_format(($this->nr / $this->total) * 100, 0) . "%" : "0%");
        }

        $cat_sources = [];
        if (is_array($this->sources) && count($this->sources)) {
            foreach ($this->sources as $src) {
                $cat_sources[] = $src->get_ID();
            }
        }

        $sources   = json_encode($cat_sources);
        $link      = ($this->name != 'Unassigned' ? "<a href='javascript:void(0);' onclick='open_echecklist({$this->id});'>{$this->name}</a>" : $this->name);
        $analyst   = ($this->analyst ? "&nbsp;&nbsp;({$this->analyst})" : "");
        $export    = ($this->name != 'Unassigned' ?
            "<a href='/ste/export.php?cat={$this->id}' target='_new'>" .
            "<img src='/img/export.jpg' class='cat_icons' title='Export eChecklist' />" .
            "</a>" :
            "<img src='/img/move.jpg' class='cat_icons' title='Autocategorize targets' onclick='javascript:auto_cat();' />"
            );
        $vert_menu = ($this->name != 'Unassigned' ? $this->get_Vert_Option_Menu() : '');
        return <<<EOC
<div class='table-cat' id='cat_{$this->id}'>
    <input type='hidden' id='cat_{$this->id}_dl' value='0' />
    <input type='hidden' id='cat_sources_{$this->id}' value='{$sources}' />
    <span class='cat-cell' style='width:250px;'>
        <span class='cat-cell'>
            <i class='far toggler fa-plus-square' id='collapse_{$this->id}' data-id='{$this->id}' title='Expand/Collapse All'> </i>
        </span>
        <span class='cat-cell'>
            <img src='/img/select_all.png' class='cat_icons' title='Select All/None' onclick='javascript:select("{$this->id}");' />
        </span>
        <span class='open cat-cell' style='width:50px;' title='Open'>{$open}</span>
        <span class='nf cat-cell' style='width:50px;' title='Not a Finding'>{$nf}</span>
        <span class='na cat-cell' style='width:50px;' title='Not Applicable'>{$na}</span>
        <span class='nr cat-cell' style='width:50px;' title='Not Reviewed'>{$nr}</span>
    </span>
    <span class='cat-cell' style='width:700px;' id='cat_name_{$this->id}'>$link&nbsp;&nbsp;({$this->tgt_count})$analyst</span>
    <span class='cat-cell' style='width:250px;'>
        <span class='cat-cell' style=''>{$export}</span>
        <span class='cat-cell' style=''>
            <form method='post' style='display: inline;' action='index.php' id='assign_{$this->id}'>
                <input type='hidden' name='action' value='assign' />
                <input type='hidden' name='ste' value='{$this->ste_id}' />
                <input type='hidden' name='cat_id' value='{$this->id}' />
                <input type='hidden' name='analyst' id='analyst_{$this->id}' value='' />
                <img src='/img/assign-to.png' class='cat_icons' title='Assign category to analyst' onclick='assign("{$this->id}");' />
            </form>
        </span>
        $vert_menu
    </span>
</div>
EOC;
    }

    public function getTaskStatusCategoryRow()
    {
        $auto = 'NR';
        $man  = 'NR';
        $data = 'NR';
        $fp   = 'NR';
    }

    /**
     * Function to create vertical menu
     *
     * @return string
     */
    public function get_Vert_Option_Menu()
    {
        return <<<EOC
<dl id='menu'>
    <dt onmouseover='javascript:montre("smenu{$this->id}");'>
        <img src='/img/options.png' style='width:20px;vertical-align:middle;' />
    </dt>
    <dd id='smenu{$this->id}' onmouseover='javascript:montre("smenu{$this->id}");' onmouseout='javascript:montre();'>
        <ul>
            <li><a href='/ste/target.php?ste={$this->ste_id}&cat={$this->id}' target='_blank'>Add Target</a></li>
            <li><a href='javascript:void(0);' onclick='javascript:edit_cat({$this->id});'>Edit Category</a></li>
            <li><a href='javascript:void(0);' onclick='javascript:delete_cat({$this->id});'>Delete Category</a></li>
            <li><a href='interview.php?cat={$this->id}' target='_new'>Category Interview</a></li>
            <li><a href='bulk_edit.php?cat={$this->id}'>Bulk Edit</a></li>
            <li><a href='javascript:void(0);' onclick='javascript:export_ckl({$this->id});'>Export CKL</a></li>
        </ul>
    </dd>
</dl>
EOC;
    }
}
