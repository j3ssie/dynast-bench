#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
resp=$(curl -isS -X POST "$TARGET/api/auth/login" -H 'Origin: http://evil.local' -H 'content-type: application/json' --data '{"email":"user1@bench.local","password":"User123!"}')
printf '%s' "$resp" | grep -qi 'access-control-allow-origin: http://evil.local'
printf '%s' "$resp" | grep -qi 'SameSite=None'
! printf '%s' "$resp" | grep -qi 'Secure'
