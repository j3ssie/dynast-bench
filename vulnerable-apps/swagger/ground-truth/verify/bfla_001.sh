#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_state
login user1@bench.local User123!
uid=$(user_id user1@bench.local)
curl -sf -b "$JAR" -X POST "$TARGET/api/v1/admin/users/$uid/role" -H 'content-type: application/json' -d '{"role":"admin"}' | grep -q 'admin'
[ "$(user_role user1@bench.local)" = "admin" ]
reset_state
