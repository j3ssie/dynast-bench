#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
uid=$(user_id user1@bench.local)
login user1@bench.local User123! >/dev/null
curl -fsS -b "$JAR" -X POST "$TARGET/api/users/$uid/promote" | grep -q '"isAdmin":true'
