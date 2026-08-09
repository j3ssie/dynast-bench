#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "CMD_INJECTION")
contains_in_run "$rid" "CMD-INJECTION-OK"
