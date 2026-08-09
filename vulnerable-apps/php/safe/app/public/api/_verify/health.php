<?php
require_once __DIR__ . '/../../../inc/db.php';
try { pdo()->query('SELECT 1'); $db = 'ok'; } catch (Throwable $e) { $db = 'error'; }
json_response(['status' => 'ok', 'db' => $db, 'app' => 'php']);
?>
