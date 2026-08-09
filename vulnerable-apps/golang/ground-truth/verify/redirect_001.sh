#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
headers=$(mktemp)
curl -s -D "$headers" -o /dev/null "$TARGET/goto?next=https://evil.example/"
tr -d '\r' < "$headers" | grep -q '^Location: https://evil.example/'
