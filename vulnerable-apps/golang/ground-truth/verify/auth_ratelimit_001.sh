#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
email="rate-$$@bench.local"
last=""
for i in 1 2 3 4 5 6 7; do
  last=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d "{"email":"$email","password":"nope"}")
done
[ "$last" != "429" ]
