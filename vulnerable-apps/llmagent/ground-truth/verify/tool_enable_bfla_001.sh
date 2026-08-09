#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
out=$(curl -fsS -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d '{"tool":"run_shell"}' "$TARGET/api/agents/agent-acme/tools")
printf "%s" "$out" | contains_http "run_shell"
