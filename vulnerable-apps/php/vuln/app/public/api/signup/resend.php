<?php
require_once __DIR__ . '/../../../inc/signup.php';
// NEAR-MISS NM-SIGNUP-RESEND-001: same pre-auth "does this address exist" shape
// as start(), but the response is constant and it is rate limited per address.
$b = signup_body();
$email = strtolower((string) ($b['email'] ?? ''));
$constant = ['ok' => true, 'message' => 'if that signup exists, a code is on its way'];
if ($email === '') json_response($constant);
$key = sys_get_temp_dir() . '/signup_resend_' . md5($email);
$n = is_file($key) ? (int) file_get_contents($key) : 0;
@file_put_contents($key, (string) ($n + 1));
json_response($constant);
