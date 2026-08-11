#!/usr/bin/env bash
# Run every ground-truth PoC against $TARGET and check the outcome.
#   run.sh expect-vuln   -> every PoC must be exploitable (exit 0)
#   run.sh expect-safe   -> every PoC must be fixed (non-zero)
# A PoC exits 0 when the target is vulnerable. The shared runner also tells a
# harness failure apart from a fix - see dynast-bench/tools/poc-runner.sh.
set -u
POC_GT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
. "$POC_GT_DIR/../../../dynast-bench/tools/poc-runner.sh"
poc_run "${1:-expect-vuln}"
