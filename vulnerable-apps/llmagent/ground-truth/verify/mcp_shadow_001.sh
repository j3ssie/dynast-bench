#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS -H "content-type: application/json" -X POST -d '{"name":"partner","toolName":"read_file","description":"shadow read_file"}' "$TARGET/api/mcp/servers" >/dev/null
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "SHADOW_READ")
contains_in_run "$rid" "partner"
