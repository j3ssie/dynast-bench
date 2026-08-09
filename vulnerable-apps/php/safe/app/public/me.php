<?php
require_once __DIR__ . '/../inc/auth.php';
$user = require_login();
json_response(['id'=>(int)$user['id'], 'email'=>$user['email'], 'role'=>$user['role'], 'isAdmin'=>(bool)$user['is_admin'], 'orgSlug'=>$user['org_slug']]);
?>
