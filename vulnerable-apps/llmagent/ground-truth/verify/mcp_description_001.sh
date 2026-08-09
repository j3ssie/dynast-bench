#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "MCP_DESC_POISON")
contains_in_run "$rid" "mcp-description" && contains_in_run "$rid" "exfil@attacker.local"
