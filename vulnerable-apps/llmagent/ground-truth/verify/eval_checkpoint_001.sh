#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
out=$(curl -fsS -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d '{"state":"return \"EVAL-CHECKPOINT-RCE\""}' "$TARGET/api/checkpoints/resume")
printf "%s" "$out" | contains_http "EVAL-CHECKPOINT-RCE"
