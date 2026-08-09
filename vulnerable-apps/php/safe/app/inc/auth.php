<?php
require_once __DIR__ . '/db.php';
function current_user(): ?array {
    if (empty($_SESSION['user_id'])) return null;
    $stmt = pdo()->prepare('SELECT u.*, o.slug AS org_slug FROM users u JOIN orgs o ON o.id = u.org_id WHERE u.id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    return $user ?: null;
}
function require_login(): array {
    $user = current_user();
    if (!$user) json_response(['error' => 'login required'], 401);
    return $user;
}
function login_user(array $user): void {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
}
?>
