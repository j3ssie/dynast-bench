<?php
require_once __DIR__ . '/../../../inc/signup.php';
// FIXED SIGNUP-IDOR-001: reading a draft requires the code emailed to that
// address (proof of ownership), and the code is never echoed back.
$d = find_draft($_GET['id'] ?? 0);
if (!$d) json_response(['error' => 'unknown draft'], 404);
if (!hash_equals($d['code'], (string) ($_SERVER['HTTP_X_DRAFT_CODE'] ?? ''))) json_response(['error' => 'forbidden'], 403);
unset($d['code']);
json_response($d);
