<?php
require_once __DIR__ . '/db.php';

// SIGNUP-TOKEN-001 (CWE-330/CWE-640): the emailed verification code is the last
// six digits of the wall clock, not a CSPRNG draw, so it can be recomputed
// instead of received. The safe twin uses random_int.
function signup_code(): string {
    return substr((string) time(), -6);
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
