#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
headers=$(curl -s -D - -o /dev/null "$TARGET/login?next=https://evil.example/phish")
grep -Eq '^HTTP/.* 30[1278]' <<<"$headers" && grep -qi '^Location: https://evil.example/phish' <<<"$headers"
