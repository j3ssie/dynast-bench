#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
a=$(curl -s -X POST "$TARGET/api/auth/login" -H "$json_ct" -d '{"email":"nobody@bench.local","password":"x"}')
b=$(curl -s -X POST "$TARGET/api/auth/login" -H "$json_ct" -d '{"email":"user1@bench.local","password":"x"}')
echo "$a" | grep -q 'No account for email'
echo "$b" | grep -q 'Bad password'
