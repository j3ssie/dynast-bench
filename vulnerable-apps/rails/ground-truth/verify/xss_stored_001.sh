#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
pid=$(post_id acme-welcome)
marker='<script>window.RAILS_STORED_XSS_19b4=1</script>'
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/api/posts/$pid/comments" --data-urlencode "body=$marker" >/dev/null
out=$(curl -s "$TARGET/posts/$pid")
echo "$out" | grep -q "$marker"
