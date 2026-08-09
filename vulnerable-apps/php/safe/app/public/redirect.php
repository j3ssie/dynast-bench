<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$next = $_GET['next'] ?? '/';
if (!str_starts_with($next, '/') || str_starts_with($next, '//')) { $next = '/'; }
header('Location: ' . $next);
?>
