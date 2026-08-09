#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_app
tok=$(login user1@bench.local User123!)
ok=0
for i in $(seq 1 12); do
  (curl --max-time 3 -fsS -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d "{\"prompt\":\"race-$i\"}" "$TARGET/api/runs" >/tmp/llmagent-race-$i.json 2>/dev/null && echo ok >/tmp/llmagent-race-$i.ok) &
done
wait
ok=$(ls /tmp/llmagent-race-*.ok 2>/dev/null | wc -l | tr -d " ")
rm -f /tmp/llmagent-race-*
[ "$ok" -gt 5 ]
