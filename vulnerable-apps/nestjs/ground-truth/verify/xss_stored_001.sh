#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
id=$(post_id welcome-acme)
marker='<script>window.NEST_XSS_STORED=1</script>'
login user1@bench.local User123!
json=$(python3 -c 'import json,sys; print(json.dumps({"body": sys.argv[1]}))' "$marker")
curl -s -b "$JAR" -X POST "$TARGET/api/posts/$id/comments" -H 'content-type: application/json' --data-binary "$json" >/dev/null
body=$(curl -s "$TARGET/posts/$id/html")
grep -Fq "$marker" <<<"$body"
