#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
trap 'curl -s -H "$VT" "$TARGET/api/_verify/reset-user1" >/dev/null 2>&1 || true' EXIT
login 'user1@bench.local' 'User123!'
curl -s -b "$JAR" -c "$JAR" -X POST "$TARGET/profile" --data-urlencode 'role=admin' >/dev/null
curl -s -b "$JAR" "$TARGET/admin/users" | grep -F 'ADMIN-USERS'
