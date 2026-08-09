<?php
require_once __DIR__ . '/../inc/auth.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = require_login();
    $stmt = pdo()->prepare('INSERT INTO comments (post_id,user_id,body) VALUES (?,?,?)');
    $stmt->execute([(int)$_POST['post_id'], $user['id'], $_POST['body'] ?? '']);
    json_response(['ok' => true]);
}
$postId = (int)($_GET['post_id'] ?? 1);
$stmt = pdo()->prepare('SELECT body FROM comments WHERE post_id = ? ORDER BY id');
$stmt->execute([$postId]);
foreach ($stmt as $row) { echo '<p class="comment">' . htmlspecialchars($row['body'], ENT_QUOTES) . '</p>'; }
?>
