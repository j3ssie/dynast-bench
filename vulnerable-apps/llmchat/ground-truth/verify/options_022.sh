#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"options probe","options":{"num_predict":99999},"use_cache":false}' | grep -q '"num_predict":99999'
