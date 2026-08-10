<?php
require_once __DIR__ . '/../../../inc/signup.php';
// FIXED SIGNUP-ENUM-001: step 1 answers the same way whether or not the address
// is already registered - always 200 with a draft id.
$b = signup_body();
$email = (string) ($b['email'] ?? '');
if ($email === '') json_response(['error' => 'email required'], 400);
$ins = pdo()->prepare('INSERT INTO signup_drafts (email, code) VALUES (?, ?)');
$ins->execute([$email, signup_code()]);
json_response(['draftId' => (int) pdo()->lastInsertId(), 'step' => 'verify']);
