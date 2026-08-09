<?php
require_once __DIR__ . '/../../../inc/db.php';
$token = $_SERVER['HTTP_X_VERIFY_TOKEN'] ?? '';
if ($token !== (getenv('VERIFY_TOKEN') ?: 'benchsecret')) json_response(['error' => 'forbidden'], 403);
$slug = $_GET['slug'] ?? '';
$stmt = pdo()->prepare('SELECT p.*, u.email AS author_email, o.slug AS org_slug FROM posts p JOIN users u ON u.id = p.author_id JOIN orgs o ON o.id = p.org_id WHERE p.slug = ?');
$stmt->execute([$slug]);
$p = $stmt->fetch();
if (!$p) json_response(['exists' => false]);
json_response(['exists'=>true, 'id'=>(int)$p['id'], 'slug'=>$p['slug'], 'status'=>$p['status'], 'authorEmail'=>$p['author_email'], 'orgSlug'=>$p['org_slug']]);
?>
