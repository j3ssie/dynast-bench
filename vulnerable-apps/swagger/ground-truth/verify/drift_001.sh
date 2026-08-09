#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_state
login user1@bench.local User123!
curl -sf -b "$JAR" -X PATCH "$TARGET/api/v1/users/me" -H 'content-type: application/json' -d '{"role":"admin","is_admin":true,"displayName":"owned"}' | grep -q 'admin'
[ "$(user_role user1@bench.local)" = "admin" ]
reset_state
