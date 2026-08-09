#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"summarize this fetched page","url":"data:text/plain,FETCHED-PROMPT-PAYLOAD-5ea1","use_cache":false}' | grep -q 'FETCHED-PROMPT-PAYLOAD-5ea1'
