<?php
require_once __DIR__ . '/../inc/auth.php';
require_login();
$rows = pdo()->query('SELECT email, role, is_admin FROM users ORDER BY id')->fetchAll();
json_response(['users' => $rows]);
?>
