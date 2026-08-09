#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/chat" -d '{"prompt":"model probe","model":"attacker-model:latest","keep_alive":-1,"use_cache":false}' | grep -Eq 'attacker-model:latest|"keep_alive":-1'
