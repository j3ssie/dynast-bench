#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_quota
login user1@bench.local User123!
ok=0
for i in 1 2 3 4 5 6; do
  if auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"quota probe","use_cache":false}' | grep -q 'conversation_id'; then ok=$((ok+1)); fi
done
[ "$ok" -eq 6 ]
