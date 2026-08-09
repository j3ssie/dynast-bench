<?php
require_once __DIR__ . '/../inc/db.php';
$q = $_GET['q'] ?? '';
echo "<h1>Search: $q</h1>";
$sql = "SELECT slug,title,body,status FROM posts WHERE status = 'published' AND title LIKE '%$q%'";
foreach (pdo()->query($sql) as $row) {
    echo "<article><h2>{$row['title']}</h2><p>{$row['body']}</p><em>{$row['status']}</em></article>";
}
function safe_search_near_miss(PDO $pdo, string $term): array {
    $stmt = $pdo->prepare("SELECT slug,title FROM posts WHERE status = ? AND title LIKE ?");
    $stmt->execute(['published', "%$term%"]);
    return $stmt->fetchAll();
}
?>
