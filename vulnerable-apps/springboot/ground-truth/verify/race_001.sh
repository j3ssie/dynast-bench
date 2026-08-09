#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS -X POST "$TARGET/api/invites/reset" >/dev/null
for i in 1 2 3 4 5 6; do curl -s -X POST "$TARGET/api/invites" -H "$json_ct" -d "{\"email\":\"race$i@bench.local\"}" >/dev/null & done
wait
curl -fsS "$TARGET/api/invites/count" | python3 -c 'import sys,json; assert json.load(sys.stdin)["count"] > 3'
