#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
body=$(curl -sf -b "$JAR" "$TARGET/api/v1/admin/users")
printf '%s' "$body" | grep -q 'passwordHash'
printf '%s' "$body" | grep -q 'resetToken'
