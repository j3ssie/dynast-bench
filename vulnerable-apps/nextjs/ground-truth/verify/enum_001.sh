#!/usr/bin/env bash
# ENUM-001 (CWE-204): login returns distinct status for unknown-user vs wrong-password.
set -e; . "$(dirname "$0")/_lib.sh"
c1=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"nope@bench.local","password":"x"}')
c2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"user1@bench.local","password":"wrong"}')
[ "$c1" != "$c2" ]
