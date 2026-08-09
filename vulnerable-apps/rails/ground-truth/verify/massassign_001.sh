#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
out=$(curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'user[display_name]=Mallory' \
  --data-urlencode 'user[role]=admin' \
  --data-urlencode 'user[is_admin]=true')
echo "$out" | grep -q '"role":"admin"'
