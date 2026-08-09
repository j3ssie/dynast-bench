#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -c "$JAR" "$TARGET/api/_verify/health" >/dev/null
before=$(cookie_val "$JAR")
curl -s -b "$JAR" -c "$JAR" -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"user1@bench.local","password":"User123!"}' >/dev/null
after=$(cookie_val "$JAR")
[ -n "$before" ] && [ "$before" = "$after" ]
