<?php
require_once __DIR__ . '/../inc/bootstrap.php';
$url = $_GET['url'] ?? '';
$parts = parse_url($url);
$host = $parts['host'] ?? '';
if (!in_array($parts['scheme'] ?? '', ['http', 'https'], true) || !in_array($host, ['example.com'], true)) {
    http_response_code(400);
    echo 'blocked';
    exit;
}
echo file_get_contents($url);
?>
