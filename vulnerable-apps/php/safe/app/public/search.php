<?php
require_once __DIR__ . '/../inc/db.php';
$q = $_GET['q'] ?? '';
echo '<h1>Search: ' . htmlspecialchars($q, ENT_QUOTES) . '</h1>';
$stmt = pdo()->prepare("SELECT slug,title,body,status FROM posts WHERE status = ? AND title LIKE ?");
$stmt->execute(['published', "%$q%"]);
foreach ($stmt as $row) {
    echo '<article><h2>' . htmlspecialchars($row['title'], ENT_QUOTES) . '</h2><p>' . htmlspecialchars($row['body'], ENT_QUOTES) . '</p><em>' . htmlspecialchars($row['status'], ENT_QUOTES) . '</em></article>';
}
function safe_search_near_miss(PDO $pdo, string $term): array {
    $stmt = $pdo->prepare("SELECT slug,title FROM posts WHERE status = ? AND title LIKE ?");
    $stmt->execute(['published', "%$term%"]);
    return $stmt->fetchAll();
}
?>
