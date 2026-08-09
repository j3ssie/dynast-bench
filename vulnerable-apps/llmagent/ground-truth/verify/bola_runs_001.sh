#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok1=$(login user1@bench.local User123!)
tok2=$(login user2@bench.local User123!)
rid=$(start_run "$tok1" "SQL_WRITE")
out=$(curl -fsS -H "authorization: Bearer $tok2" "$TARGET/api/runs/$rid")
printf "%s" "$out" | contains_http "$rid"
