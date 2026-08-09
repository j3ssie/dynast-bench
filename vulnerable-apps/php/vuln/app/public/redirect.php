<?php
require_once __DIR__ . '/../inc/bootstrap.php';
header('Location: ' . ($_GET['next'] ?? '/'));
?>
