<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$base = realpath(__DIR__ . '/downloads');
$name = basename($_GET['file'] ?? 'report.txt');
$path = realpath($base . '/' . $name);
if ($path === false || !str_starts_with($path, $base . DIRECTORY_SEPARATOR)) { http_response_code(404); exit; }
readfile($path);
?>
