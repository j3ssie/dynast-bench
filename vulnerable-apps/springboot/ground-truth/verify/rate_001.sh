#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
code=0
for i in 1 2 3 4 5 6 7; do code=$(curl -s -o /tmp/sb-rate.$$ -w '%{http_code}' -X POST "$TARGET/api/auth/login" -H "$json_ct" -d '{"email":"user1@bench.local","password":"wrong"}'); done
rm -f /tmp/sb-rate.$$
[ "$code" = "401" ]
