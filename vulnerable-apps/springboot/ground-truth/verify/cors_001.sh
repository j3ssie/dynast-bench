#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/public/cors")
echo "$out" | grep -qi 'Access-Control-Allow-Origin: https://evil.example'
echo "$out" | grep -qi 'Access-Control-Allow-Credentials: true'
