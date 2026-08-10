#!/usr/bin/env bash
# SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft was
# verified, so a jump from step 1 to step 4 registers an unverified mailbox.
set -eu; . "$(dirname "$0")/_lib.sh"
EMAIL="skipper-$$@bench.local"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\"}" | jget draftId)
[ -n "$DRAFT" ]
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' \
  -d "{\"draftId\":$DRAFT,\"password\":\"Skipped123!\"}" >/dev/null
# the account exists (verify API resolves it)
[ -n "$(user_id "$EMAIL")" ]
