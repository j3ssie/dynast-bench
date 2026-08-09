#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "MCP_BEARER")
contains_in_run "$rid" "USER-BEARER-FORWARDED"
