#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
h=$(mktemp)
curl -s -D "$h" -o /dev/null -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"user1@bench.local","password":"User123!"}'
line=$(grep -i '^Set-Cookie: bench_session=' "$h" | tr -d '\r')
rm -f "$h"
echo "$line" | grep -q 'bench_session=' && ! echo "$line" | grep -Eiq 'HttpOnly|Secure|SameSite'
