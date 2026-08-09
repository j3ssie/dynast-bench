#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
trap 'curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset-acme" >/dev/null || true' EXIT
curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset-acme" >/dev/null
login user1@bench.local User123!
for i in $(seq 1 8); do
  curl -s --max-time 5 -b "$JAR" -X POST "$TARGET/api/invites" -H 'content-type: application/json' -d "{\"email\":\"race$i@bench.local\"}" >/tmp/fastapi_race_$i.out &
done
wait
ok=$(grep -l '"id"' /tmp/fastapi_race_*.out 2>/dev/null | wc -l | tr -d ' ')
[ "$ok" -gt 3 ]
