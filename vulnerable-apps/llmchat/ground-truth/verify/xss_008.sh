#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
CID=$(auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"[[EMIT_XSS]]","use_cache":false}' | python3 -c 'import sys,json; print(json.load(sys.stdin).get("conversation_id",""))')
get_auth "$TARGET/api/conversations/$CID/html" | grep -q "<img src=x onerror=alert('llmchat-xss')>"
