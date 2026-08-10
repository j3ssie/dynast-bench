#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
E="skipper-$$@bench.local"
D=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' -d "{\"email\":\"$E\"}" | json_get draftId)
[ -n "$D" ]
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' -d "{\"draftId\":$D,\"password\":\"Skipped123!\"}" >/dev/null
[ -n "$(user_id "$E")" ]
