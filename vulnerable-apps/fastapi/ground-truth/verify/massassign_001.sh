#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
trap 'curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset-acme" >/dev/null || true' EXIT
login user1@bench.local User123!
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' -d '{"role":"admin","is_admin":true}' | grep -q '"role":"admin"'
