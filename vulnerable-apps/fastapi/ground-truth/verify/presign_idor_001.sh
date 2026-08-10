#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
aid=$(curl -s -H "$VT" "$TARGET/api/_verify/attachment?filename=globex-plan.txt" | json_get id)
[ -n "$aid" ]
resp=$(curl -s -b "$JAR" "$TARGET/api/attachments/$aid/url")
printf '%s' "$resp" | grep -q 'globex'
url=$(printf '%s' "$resp" | json_get url)
curl -s "$TARGET$url" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
