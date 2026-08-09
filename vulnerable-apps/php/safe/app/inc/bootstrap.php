<?php
session_start();
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, ['http://127.0.0.1:3000', 'http://localhost:3000'], true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Headers: Content-Type, X-Verify-Token');
}
function json_response($data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}
?>
