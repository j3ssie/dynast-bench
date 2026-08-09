#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "UNRESTRICTED_SHELL")
curl --max-time 5 -fsS -H "authorization: Bearer $tok" -X POST "$TARGET/api/runs/$rid/export" >/dev/null
out=$(curl --max-time 5 -fsS "$TARGET/exports/")
printf "%s" "$out" | contains_http "$rid.json"
