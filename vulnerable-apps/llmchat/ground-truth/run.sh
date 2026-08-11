#!/usr/bin/env bash
# Run every llmchat ground-truth PoC against $TARGET and check the outcome.
#   run.sh expect-vuln   -> every PoC must be exploitable (exit 0)
#   run.sh expect-safe   -> every PoC must be fixed (non-zero)
# A PoC exits 0 when the target is vulnerable. The shared runner also tells a
# harness failure apart from a fix - see dynast-bench/tools/poc-runner.sh.
set -u
POC_GT_DIR="$(cd "$(dirname "$0")" && pwd)"
export LLM_BACKEND="${LLM_BACKEND:-stub}"

# ingest.sh seeds the corpus the other PoCs attack; it is a fixture, not a PoC.
POC_SKIP="ingest.sh"

# shellcheck source=/dev/null
. "$POC_GT_DIR/../../../dynast-bench/tools/poc-runner.sh"
echo ">> llm_backend=$LLM_BACKEND"
poc_run "${1:-expect-vuln}"
