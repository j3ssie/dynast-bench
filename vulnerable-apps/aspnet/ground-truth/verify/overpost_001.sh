#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/api/users/me" -H 'content-type: application/json' -d '{"displayName":"u1","role":"admin","isAdmin":true}' >/dev/null
ok=1; curl -s -b "$JAR" "$TARGET/api/reports/admin-summary" | grep -q 'ADMIN-SUMMARY-ASPNET' || ok=0
curl -s -b "$JAR" -X POST "$TARGET/api/users/me" -H 'content-type: application/json' -d '{"role":"user","isAdmin":false}' >/dev/null || true
[ "$ok" = 1 ]
