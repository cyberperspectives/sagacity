<?php

$end = new DateTime();

$diff = $start->diff($end);

print $diff->format("%H:%I:%S");
$log->script_log("Script runtiime: ".$diff->format("%H:%I:%S"));
