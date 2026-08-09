<?php
require_once __DIR__ . '/../inc/auth.php';
$user = require_login();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['avatar'])) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($_FILES['avatar']['tmp_name']);
        if (!in_array($mime, ['image/png', 'image/jpeg'], true)) json_response(['error' => 'invalid avatar'], 400);
        $name = bin2hex(random_bytes(8)) . ($mime === 'image/png' ? '.png' : '.jpg');
        $dest = __DIR__ . '/uploads/' . $name;
        move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
        json_response(['url' => '/uploads/' . $name]);
    }
    if (isset($_POST['display_name'])) {
        $stmt = pdo()->prepare('UPDATE users SET display_name = ? WHERE id = ?');
        $stmt->execute([$_POST['display_name'], $user['id']]);
    }
    json_response(['ok' => true]);
}
?>
<form method="post" enctype="multipart/form-data"><input name="display_name"><input name="role"><input type="file" name="avatar"><button>save</button></form>
