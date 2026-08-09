<?php
require_once __DIR__ . '/../../../inc/db.php';
$token = $_SERVER['HTTP_X_VERIFY_TOKEN'] ?? '';
if ($token !== (getenv('VERIFY_TOKEN') ?: 'benchsecret')) json_response(['error' => 'forbidden'], 403);
$email = $_GET['email'] ?? '';
$stmt = pdo()->prepare('SELECT u.*, o.slug AS org_slug FROM users u JOIN orgs o ON o.id = u.org_id WHERE u.email = ?');
$stmt->execute([$email]);
$u = $stmt->fetch();
if (!$u) json_response(['exists' => false]);
json_response(['exists'=>true, 'id'=>(int)$u['id'], 'role'=>$u['role'], 'isAdmin'=>(bool)$u['is_admin'], 'verified'=>(bool)$u['verified'], 'orgSlug'=>$u['org_slug']]);
?>
