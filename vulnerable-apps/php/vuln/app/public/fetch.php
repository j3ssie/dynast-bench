<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$url = $_GET['url'] ?? '';
echo file_get_contents($url);
?>
