#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
token=$(api_token user1@bench.local User123!)
curl -sf -H "authorization: Bearer $token" "$TARGET/api/_verify/health" >/dev/null
curl -sf "$TARGET/api/v1/internal/audit" | grep -q "$token"
