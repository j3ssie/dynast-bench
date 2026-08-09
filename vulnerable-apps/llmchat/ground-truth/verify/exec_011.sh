#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/tools/calc" -d '{"prompt":"[[EMIT_EXEC]]"}' | grep -q 'RCE-LLMCHAT-OK'
