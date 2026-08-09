<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$file = $_GET['file'] ?? __DIR__ . '/downloads/report.txt';
readfile($file);
?>
