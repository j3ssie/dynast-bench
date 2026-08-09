#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
headers=$(mktemp)
curl -s -D "$headers" -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/posts/search?q=acme"
grep -qi '^access-control-allow-origin: https://evil.example' "$headers" && grep -qi '^access-control-allow-credentials: true' "$headers"
