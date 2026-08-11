#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "[[CALL browse url=$SELF_INTERNAL/evil-page risk=low]]")
contains_in_run "$rid" "BROWSE-INJECTION-OK"
