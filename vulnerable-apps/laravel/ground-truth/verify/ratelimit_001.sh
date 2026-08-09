#!/usr/bin/env bash
# RATELIMIT-001 (CWE-307): the login route has no throttle, so many rapid failed
# attempts never trigger a 429. The safe twin adds a per-identity failure limiter
# (a 429 appears). A dedicated probe identity is used so this never affects other
# PoCs' logins.
set -eu
. "$(dirname "$0")/_lib.sh"
TOKEN="$(csrf_from /login)"
seen429=0
for i in $(seq 1 12); do
  c=$(curl -s -o /dev/null -w "%{http_code}" -c "$JAR" -b "$JAR" -X POST "$TARGET/login" \
        -d "_token=$TOKEN" --data-urlencode "email=rlprobe@bench.local" --data-urlencode "password=wrong$i")
  [ "$c" = "429" ] && seen429=1
done
# vulnerable => never rate-limited
[ "$seen429" -eq 0 ]
