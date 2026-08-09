#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
headers=$(curl -sI -X OPTIONS "$TARGET/api/auth/login" -H 'Origin: https://evil.example' -H 'Access-Control-Request-Headers: content-type')
grep -qi 'access-control-allow-origin: https://evil.example' <<<"$headers" && grep -qi 'access-control-allow-credentials: true' <<<"$headers"
