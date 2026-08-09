#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "UNRESTRICTED_SHELL")
contains_in_run "$rid" "AGENCY-SHELL-OK"
