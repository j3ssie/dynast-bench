#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
headers=$(mktemp)
curl -s -D "$headers" -o /dev/null "$TARGET/goto?next=https://evil.example/phish"
grep -qi '^location: https://evil.example/phish' "$headers"
