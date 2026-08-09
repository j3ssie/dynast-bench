#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
resp=$(curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"nobody@bench.local","password":"x"}')
printf '%s' "$resp" | grep -q 'user not found'
