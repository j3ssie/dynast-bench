#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
headers=$(curl -s -D - -o /dev/null "$TARGET/goto?next=https://evil.example/landing")
printf '%s' "$headers" | tr -d '\r' | grep -qi '^location: https://evil.example/landing'
