<?php
require_once __DIR__ . '/../../../inc/signup.php';
// FIXED SIGNUP-MASSASSIGN-001: only the one field this step owns is written;
// role and org_slug are never client-writable.
$b = signup_body();
$d = find_draft($b['draftId'] ?? 0);
if (!$d) json_response(['error' => 'unknown draft'], 404);
pdo()->prepare('UPDATE signup_drafts SET display_name = ? WHERE id = ?')->execute([(string) ($b['display_name'] ?? ''), $d['id']]);
$d = find_draft($d['id']);
json_response(['ok' => true, 'step' => 'complete', 'displayName' => $d['display_name']]);
