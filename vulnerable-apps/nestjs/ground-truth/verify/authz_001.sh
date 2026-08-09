#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
body=$(curl -s -b "$JAR" "$TARGET/api/admin/users")
grep -q 'admin@bench.local' <<<"$body"
