#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' -d '{"display_name":"Acme User","role":"admin"}' >/dev/null
role=$(user_role user1@bench.local)
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' -d '{"role":"user"}' >/dev/null || true
[ "$role" = "admin" ]
