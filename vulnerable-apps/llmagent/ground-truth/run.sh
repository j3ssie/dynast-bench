#!/usr/bin/env bash
# Run every llmagent ground-truth PoC against $TARGET and check the outcome.
#   run.sh expect-vuln   -> every PoC must be exploitable (exit 0)
#   run.sh expect-safe   -> every PoC must be fixed (non-zero)
# A PoC exits 0 when the target is vulnerable. The shared runner also tells a
# harness failure apart from a fix - see dynast-bench/tools/poc-runner.sh.
set -u
POC_GT_DIR="$(cd "$(dirname "$0")" && pwd)"

# An agent loop can sit there thinking, so these PoCs need real budgets rather
# than the fleet default. On the safe twin the agent refuses immediately, so a
# PoC still running after 8s is stuck rather than slow - except the quota race,
# which deliberately holds concurrent requests open.
poc_timeout() {
  if [ "$2" = expect-vuln ]; then echo 75
  elif [ "$1" = quota_race_001.sh ]; then echo 35
  else echo 8
  fi
}

# shellcheck source=/dev/null
. "$POC_GT_DIR/../../../dynast-bench/tools/poc-runner.sh"
poc_run "${1:-expect-vuln}"
