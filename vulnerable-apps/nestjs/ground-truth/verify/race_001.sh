#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
prefix="race$(date +%s%N)"
cleanup_invites "$prefix"
login user1@bench.local User123!
for i in 1 2 3 4 5; do
  curl -s -b "$JAR" -X POST "$TARGET/api/invites" -H 'content-type: application/json' -d "{\"email\":\"$prefix-$i@example.test\"}" >/dev/null &
done
wait
count=$(invite_count "$prefix")
cleanup_invites "$prefix"
[ "$count" -gt 3 ]
