#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
resp=$(curl -sf -b "$JAR" -X POST "$TARGET/api/v1/uploads" -F 'file=@/etc/hosts;filename=../swagger_escape.txt')
printf '%s' "$resp" | grep -q '"escaped":true'
