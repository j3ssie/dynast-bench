#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_acme
login user1@bench.local User123!
for i in 1 2 3; do
  curl -s -b "$JAR" -X POST "$TARGET/api/invites" -H 'content-type: application/json' -d "{\"email\":\"race-$i-$$@bench.local\"}" >/dev/null &
done
wait
count=$(curl -s -b "$JAR" "$TARGET/api/billing/status" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("inviteCount",0))')
[ "$count" -gt 1 ]
