#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
resp=$(curl -si -H 'Origin: https://evil.example' "$TARGET/api/_verify/health.php")
printf '%s' "$resp" | grep -qi 'Access-Control-Allow-Origin: https://evil.example'
printf '%s' "$resp" | grep -qi 'Access-Control-Allow-Credentials: true'
