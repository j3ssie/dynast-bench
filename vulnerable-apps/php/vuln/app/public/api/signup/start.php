<?php
require_once __DIR__ . '/../../../inc/signup.php';
// SIGNUP-ENUM-001 (CWE-204): step 1 answers 409 for a registered address and 200
// for an unknown one - a pre-auth enumeration oracle. The safe twin always 200s.
$b = signup_body();
$email = (string) ($b['email'] ?? '');
if ($email === '') json_response(['error' => 'email required'], 400);
$st = pdo()->prepare('SELECT id FROM users WHERE email = ?');
$st->execute([$email]);
if ($st->fetch()) json_response(['error' => 'that email is already registered', 'registered' => true], 409);
$ins = pdo()->prepare('INSERT INTO signup_drafts (email, code) VALUES (?, ?)');
$ins->execute([$email, signup_code()]);
json_response(['draftId' => (int) pdo()->lastInsertId(), 'step' => 'verify']);
