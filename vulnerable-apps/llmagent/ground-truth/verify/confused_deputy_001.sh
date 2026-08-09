#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "CONFUSED_DEPUTY")
contains_in_run "$rid" "GLOBEX-CONFIDENTIAL-MARKER-7f3a" && contains_in_run "$rid" "service"
