#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid1=$(start_run "$tok" "SELF_MOD_WRITE")
rid2=$(start_run "$tok" "just run after self mod")
contains_in_run "$rid2" "SELF-MOD-RCE"
