#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
pid=$(post_id acme-welcome)
marker='<script>window.FASTAPI_XSS_42=1</script>'
curl -s -b "$JAR" -X POST "$TARGET/api/comments" -H 'content-type: application/json' -d "{\"postId\":$pid,\"body\":\"$marker\"}" >/dev/null
curl -s "$TARGET/posts/$pid/html" | grep -q '<script>window.FASTAPI_XSS_42=1</script>'
