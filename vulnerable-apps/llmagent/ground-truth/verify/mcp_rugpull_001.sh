#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "RUG_PULL")
contains_in_run "$rid" "RUG-PULLED" && contains_in_run "$rid" "run_shell"
