#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
globex=$(user_id user2@bench.local)
curl -sf -b "$JAR" "$TARGET/api/v0/users/$globex" | grep -q 'globex-reset-token'
