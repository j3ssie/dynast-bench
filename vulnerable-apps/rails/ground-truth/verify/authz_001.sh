#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
uid=$(user_id user1@bench.local)
login user1@bench.local User123!
out=$(curl -s -b "$JAR" -X POST "$TARGET/api/users/$uid/promote")
echo "$out" | grep -q '"role":"admin"'
