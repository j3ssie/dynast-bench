#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
flush_cache
login user2@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"cache-probe"}' >/dev/null
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"cache-probe"}' | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
