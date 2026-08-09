#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -X POST -H "$VT" "$TARGET/api/_verify/invites/reset" >/dev/null
for i in 1 2 3 4 5 6 7 8; do curl -s -X POST "$TARGET/api/invite" -H 'content-type: application/json' -d "{\"email\":\"r$i@bench.local\"}" >/dev/null & done
wait
count=$(curl -s "$TARGET/api/invite/count" | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])')
curl -s -X POST -H "$VT" "$TARGET/api/_verify/invites/reset" >/dev/null
[ "$count" -gt 3 ]
