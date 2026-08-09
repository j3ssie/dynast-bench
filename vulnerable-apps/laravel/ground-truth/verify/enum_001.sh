#!/usr/bin/env bash
# ENUM-001 (CWE-204): login returns different messages for an unknown email vs a
# wrong password, so valid accounts are enumerable.
set -eu
. "$(dirname "$0")/_lib.sh"
TOKEN="$(csrf_from /login)"
M1=$(curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/login" -d "_token=$TOKEN" \
      --data-urlencode "email=nobody-$RANDOM@bench.local" --data-urlencode "password=x")
M2=$(curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/login" -d "_token=$TOKEN" \
      --data-urlencode "email=user1@bench.local" --data-urlencode "password=wrongpw")
[ -n "$M1" ] && [ -n "$M2" ] && [ "$M1" != "$M2" ]
