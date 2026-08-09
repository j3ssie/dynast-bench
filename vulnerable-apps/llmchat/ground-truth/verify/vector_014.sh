#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"Globex confidential draft policy","collection_id":"globex-support","use_cache":false}' | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
