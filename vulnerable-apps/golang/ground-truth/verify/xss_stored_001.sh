#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_acme
login user1@bench.local User123!
pid=$(post_id acme-welcome)
curl -s -b "$JAR" -X POST "$TARGET/api/comments" -H 'content-type: application/json' -d "{\"postId\":$pid,\"body\":\"<script>GO-XSS-STORED</script>\"}" >/dev/null
curl -s "$TARGET/posts/$pid/html" | grep -q '<script>GO-XSS-STORED</script>'
