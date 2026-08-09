#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s -X POST "$TARGET/api/auth/reset" -H 'content-type: application/json' -d '{"email":"user1@bench.local"}')
grep -Eq '"token":"[0-9a-f]{32}"' <<<"$body"
