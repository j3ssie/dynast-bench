<?php
require_once __DIR__ . '/../inc/auth.php';
$user = require_login();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['avatar'])) {
        $name = basename($_FILES['avatar']['name']);
        $dest = __DIR__ . '/uploads/' . $name;
        move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
        json_response(['url' => '/uploads/' . $name]);
    }
    $allowed = ['display_name', 'role', 'is_admin'];
    foreach ($allowed as $field) {
        if (isset($_POST[$field])) {
            $stmt = pdo()->prepare("UPDATE users SET $field = ? WHERE id = ?");
            $stmt->execute([$_POST[$field], $user['id']]);
        }
    }
    json_response(['ok' => true]);
}
?>
<form method="post" enctype="multipart/form-data"><input name="display_name"><input name="role"><input type="file" name="avatar"><button>save</button></form>
