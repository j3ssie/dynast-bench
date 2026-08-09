#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_app
tok2=$(login user2@bench.local User123!)
tok1=$(login user1@bench.local User123!)
ridA=$(start_run "$tok2" "MEMORY_POISON")
ridB=$(start_run "$tok1" "USE_MEMORY")
contains_in_run "$ridB" "MEMORY-POISONED"
