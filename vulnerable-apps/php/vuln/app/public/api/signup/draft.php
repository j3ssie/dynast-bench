<?php
require_once __DIR__ . '/../../../inc/signup.php';
// SIGNUP-IDOR-001 (CWE-639): any draft is readable by its serial id,
// unauthenticated, and the row carries the email AND the verification code
// emailed to it - count down to walk every registration in progress.
$d = find_draft($_GET['id'] ?? 0);
if (!$d) json_response(['error' => 'unknown draft'], 404);
json_response($d);
