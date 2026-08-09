<?php
require_once __DIR__ . '/../inc/auth.php';
$user = require_login();
if (!$user['is_admin'] && $user['role'] !== 'admin') json_response(['error' => 'admin required'], 403);
$rows = pdo()->query('SELECT email, role, is_admin FROM users ORDER BY id')->fetchAll();
json_response(['users' => $rows]);
?>
