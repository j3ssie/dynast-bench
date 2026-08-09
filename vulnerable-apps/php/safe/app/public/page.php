<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$page = $_GET['page'] ?? 'home';
$pages = ['home' => __DIR__ . '/pages/home.php'];
include($pages[$page] ?? $pages['home']);
function allowed_page_near_miss(string $name): string {
    $pages = ['home' => __DIR__ . '/pages/home.php'];
    return $pages[$name] ?? $pages['home'];
}
?>
