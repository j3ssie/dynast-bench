#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -D - -o /dev/null "$TARGET/login?returnUrl=https://evil.example/phish" | tr -d '\r' | grep -qi '^Location: https://evil.example/phish'
