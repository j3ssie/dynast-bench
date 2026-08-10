<?php
require_once __DIR__ . '/../../../inc/signup.php';
// SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft
// reached the verified state, so posting straight to it with a fresh draft id
// registers an unverified, unowned mailbox as a real user.
$b = signup_body();
$d = find_draft($b['draftId'] ?? 0);
if (!$d) json_response(['error' => 'unknown draft'], 404);
if ((int) $d['completed'] === 1) json_response(['error' => 'already completed'], 409);
$org = pdo()->prepare('SELECT id FROM orgs WHERE slug = ?');
$org->execute([$d['org_slug']]);
$org = $org->fetch();
if (!$org) json_response(['error' => 'unknown org'], 400);
$pw = password_hash((string) ($b['password'] ?? 'Changeme123!'), PASSWORD_BCRYPT);
$ins = pdo()->prepare('INSERT INTO users (org_id,email,password_hash,role,is_admin,verified,display_name) VALUES (?,?,?,?,?,?,?)');
$ins->execute([$org['id'], $d['email'], $pw, $d['role'], $d['role'] === 'admin' ? 1 : 0, (int) $d['verified'], $d['display_name'] ?: 'New User']);
pdo()->prepare('UPDATE signup_drafts SET completed = 1 WHERE id = ?')->execute([$d['id']]);
json_response(['ok' => true, 'id' => (int) pdo()->lastInsertId(), 'email' => $d['email'], 'role' => $d['role']]);
