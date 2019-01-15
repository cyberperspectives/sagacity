<?php
/**
 * File: footer.inc
 * Author: Paul Porter
 * Purpose: This file will contain all the standardized footer information
 * Created: Sep 18, 2013
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
 *  - Sep 18, 2013 - File created
 *  - Sep 1, 2016 - Updated copyright
 *  - Oct 5, 2016 - Updated copyright to be a floating div
 *  - Nov 7, 2016 - Moved VER outside the popup text
 *  - Jan 30, 2017 - Extended copyright for Cyper Perspectives to 2017
 *  - Feb 15, 2017 - Added LLC to Cyber Perspectives entry
 *  - Jan 10, 2018 - Extended copyright for Cyber Perspectives to 2018
 */
?>

<div id='copyright-text'>
  <p>Portions Copyright &copy; 2016-2018 Cyber Perspectives, LLC All rights reserved.</p>
  <p>Portions Copyright &copy; 2012-2015 Salient Federal Solutions</p>
  <p>Portions Copyright &copy; 2008-2011 Science Applications International Corp.</p>
</div>

<div id="copyright" style='left:0px;'>
  <a href='javascript:void(0);' onclick="$('#copyright-text').fadeToggle(200);">&copy;Copyright&copy;</a>&nbsp;&nbsp;
  <a href="/docs/license.txt">License Information</a>&nbsp;&nbsp;
  <a href='/help.php?topic=all' target='_blank'>User Guide</a>&nbsp;&nbsp;V<?php print (defined('VER') ? VER : ''); ?>
</div>
</body>
</html>