<?php
require_once __DIR__ . '/../inc/db.php';
$email = $_POST['email'] ?? '';
$token = bin2hex(random_bytes(32));
$stmt = pdo()->prepare('UPDATE users SET reset_token = ? WHERE email = ?');
$stmt->execute([$token, $email]);
json_response(['sent' => true]);
?>
