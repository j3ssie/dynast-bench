#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
headers=$(curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/posts/search?q=welcome")
grep -qi '^Access-Control-Allow-Origin: https://evil.example' <<<"$headers" && grep -qi '^Access-Control-Allow-Credentials: true' <<<"$headers"
