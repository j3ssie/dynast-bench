#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"trace me","use_cache":false}' >/dev/null
get_auth "$TARGET/api/_debug/traces" | grep -Eq 'jwt_secret|hardcoded-weak-secret|authorization'
