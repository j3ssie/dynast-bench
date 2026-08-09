<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$format = $_REQUEST['format'] ?? 'csv';
if (!in_array($format, ['csv', 'json'], true)) { http_response_code(400); echo 'invalid format'; exit; }
echo shell_exec('printf ' . escapeshellarg('exporting ' . $format));
?>
