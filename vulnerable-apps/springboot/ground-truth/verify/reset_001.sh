#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(predict_reset 'user2@bench.local')
curl -fsS -X POST "$TARGET/api/auth/reset/request" -H "$json_ct" -d '{"email":"user2@bench.local"}' >/dev/null
curl -fsS -X POST "$TARGET/api/auth/reset/complete" -H "$json_ct" -d "{\"token\":\"$tok\",\"password\":\"Changed123!\"}" | grep -q 'user2@bench.local'
