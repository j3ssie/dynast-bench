#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_app
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "REFUND_ABUSE")
contains_in_run "$rid" "refund_order" && contains_in_run "$rid" "\"balance\":1500"
