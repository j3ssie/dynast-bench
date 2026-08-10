<?php
require_once __DIR__ . '/../../../inc/signup.php';
// SIGNUP-MASSASSIGN-001 (CWE-915): the profile step writes any draft column named
// in the body. The wizard only sends display_name, but the draft also carries
// role and org_slug - the two fields the final step hands to the new user - so a
// crafted body registers an admin or joins another tenant.
$b = signup_body();
$d = find_draft($b['draftId'] ?? 0);
if (!$d) json_response(['error' => 'unknown draft'], 404);
foreach (['display_name', 'role', 'org_slug'] as $k) {
    if (array_key_exists($k, $b)) {
        pdo()->prepare("UPDATE signup_drafts SET $k = ? WHERE id = ?")->execute([(string) $b[$k], $d['id']]);
    }
}
$d = find_draft($d['id']);
json_response(['ok' => true, 'step' => 'complete', 'displayName' => $d['display_name']]);
