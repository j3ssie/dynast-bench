#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
for i in 1 2 3 4 5 6 7; do curl -s "$TARGET/api/auth/rate-probe" >/dev/null; done
code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/api/auth/rate-probe")
[ "$code" != "429" ]
