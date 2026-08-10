#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
E="escalate-$$@bench.local"
D=$(curl -s -X POST "$TARGET/api/signup/start" -H 'content-type: application/json' -d "{\"email\":\"$E\"}" | json_get draftId)
[ -n "$D" ]
curl -s -X POST "$TARGET/api/signup/profile" -H 'content-type: application/json' -d "{\"draftId\":$D,\"display_name\":\"M\",\"role\":\"admin\",\"org_slug\":\"globex\"}" >/dev/null
curl -s -X POST "$TARGET/api/signup/complete" -H 'content-type: application/json' -d "{\"draftId\":$D,\"password\":\"Escalate123!\"}" >/dev/null
[ "$(user_role "$E")" = "admin" ]
