<?php
require_once __DIR__ . '/db.php';

// FIXED SIGNUP-TOKEN-001: the verification code is a CSPRNG draw, unrelated to
// when the signup started, so it can only be received in the email.
function signup_code(): string {
    return str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}
// NEAR-MISS NM-SIGNUP-TOKEN-001: the same job done correctly with the CSPRNG.
function invite_token(): string {
    return bin2hex(random_bytes(32));
}
function signup_body(): array {
    $raw = file_get_contents('php://input');
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}
function find_draft($id) {
    $st = pdo()->prepare('SELECT * FROM signup_drafts WHERE id = ?');
    $st->execute([(int) $id]);
    return $st->fetch() ?: null;
}
