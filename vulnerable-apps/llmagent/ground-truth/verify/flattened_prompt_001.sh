#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "FLATTENED_PROMPT")
contains_in_run "$rid" "flattened prompt obeyed"
