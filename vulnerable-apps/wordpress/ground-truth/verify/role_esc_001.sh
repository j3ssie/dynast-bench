#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_state
login_user1
curl -s -b "$JAR" -X POST "$TARGET/wp-json/bench-tasks/v1/profile" -d "role=admin" >/dev/null
[ "$(user_role user1@bench.local)" = "admin" ]
