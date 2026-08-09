<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$format = $_REQUEST['format'] ?? 'csv';
echo shell_exec("printf 'exporting $format'");
?>
