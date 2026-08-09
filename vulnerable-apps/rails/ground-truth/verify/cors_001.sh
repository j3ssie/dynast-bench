#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
headers=$(curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/posts/search?q=Acme")
printf '%s' "$headers" | tr -d '\r' | grep -qi '^access-control-allow-origin: https://evil.example'
printf '%s' "$headers" | tr -d '\r' | grep -qi '^access-control-allow-credentials: true'
