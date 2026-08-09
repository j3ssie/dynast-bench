#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
email="nobody-rate-$RANDOM@bench.local"
code=0
for i in 1 2 3 4 5 6 7; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/login" --data-urlencode "email=$email" --data-urlencode 'password=nope')
done
[ "$code" != "429" ]
