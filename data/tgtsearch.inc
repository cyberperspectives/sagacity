<?php
/**
 * File: tgtsearch.inc
 * Author: Ryan
 * Purpose: includes the target filter fields
 * Created: Sep 7, 2016
 *
 * Copyright 2016: Cyber Perspectives, All rights reserved
 * Released under the Apache v2.0 License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Sep 7, 2016 - File created
 *  - Mar 8, 2017 - Added auto open of the target filter box
 */
$target_filter_width = 990;
include_once 'target-filter.inc';
?>

<script type='text/javascript'>
  $(function () {
    collapse_expand_data('cat-filter');
  });
</script>
