<?php
require_once __DIR__ . '/../../../inc/signup.php';
$b = signup_body();
$d = find_draft($b['draftId'] ?? 0);
if (!$d) json_response(['error' => 'unknown draft'], 404);
if ($d['code'] !== (string) ($b['code'] ?? '')) json_response(['error' => 'incorrect code'], 400);
pdo()->prepare('UPDATE signup_drafts SET verified = 1 WHERE id = ?')->execute([$d['id']]);
json_response(['ok' => true, 'step' => 'profile']);
