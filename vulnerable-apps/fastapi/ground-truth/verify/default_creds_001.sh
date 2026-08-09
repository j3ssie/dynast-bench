#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
resp=$(curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"admin","password":"admin"}')
printf '%s' "$resp" | grep -q '"ok":true'
