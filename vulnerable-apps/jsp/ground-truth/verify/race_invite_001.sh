#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -H "$VT" "$TARGET/api/_verify/cleanup-invites" >/dev/null
login 'user1@bench.local' 'User123!'
tmp=$(mktemp)
for i in $(seq 1 8); do
  curl -s -b "$JAR" -X POST "$TARGET/invite" --data-urlencode "email=race-$i-$RANDOM@bench.local" >>"$tmp" &
done
wait
ok=$(grep -o invited "$tmp" | wc -l | tr -d ' ' || true)
rm -f "$tmp"
curl -s -H "$VT" "$TARGET/api/_verify/cleanup-invites" >/dev/null
[ "$ok" -ge 2 ]
