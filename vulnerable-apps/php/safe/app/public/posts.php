<?php
require_once __DIR__ . '/../inc/auth.php';
$user = require_login();
$id = (int)($_GET['id'] ?? 0);
$stmt = pdo()->prepare('SELECT p.*, o.slug AS org_slug FROM posts p JOIN orgs o ON o.id = p.org_id WHERE p.id = ? AND p.org_id = ? AND (p.status = ? OR p.author_id = ?)');
$stmt->execute([$id, $user['org_id'], 'published', $user['id']]);
$post = $stmt->fetch();
if (!$post) json_response(['error' => 'not found'], 404);
json_response(['id'=>(int)$post['id'], 'slug'=>$post['slug'], 'title'=>$post['title'], 'body'=>$post['body'], 'status'=>$post['status'], 'orgSlug'=>$post['org_slug']]);
?>
