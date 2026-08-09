<?php
require_once __DIR__ . '/../inc/db.php';
$email = $_POST['email'] ?? '';
$token = md5($email . 'bench-reset');
$stmt = pdo()->prepare('UPDATE users SET reset_token = ? WHERE email = ?');
$stmt->execute([$token, $email]);
json_response(['sent' => true, 'token' => $token]);
?>
