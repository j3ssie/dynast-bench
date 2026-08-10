#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
D=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' -d "{\"email\":\"predict-$$@bench.local\"}" | json_get draftId)
[ -n "$D" ]
for O in 0 -1 1 -2 2 -3 3; do
  C=$(python3 -c "import time;print(int(time.time()+$O)%1000000)")
  if curl -s -X POST "$TARGET/api/signup/verify" -H 'content-type: application/json' -d "{\"draftId\":$D,\"code\":\"$C\"}" | grep -q '"ok":true'; then exit 0; fi
done
exit 1
