#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
D=$(curl -s -X POST "$TARGET/api/signup/start.php" -H 'content-type: application/json' -d "{\"email\":\"predict-$$@bench.local\"}" | json_get draftId)
[ -n "$D" ]
for O in 0 -1 1 -2 2 -3 3; do
  C=$(python3 -c "import time;print(str(int(time.time())+$O)[-6:])")
  if curl -s -X POST "$TARGET/api/signup/verify.php" -H 'content-type: application/json' -d "{\"draftId\":$D,\"code\":\"$C\"}" | grep -q '"ok":true'; then exit 0; fi
done
exit 1
