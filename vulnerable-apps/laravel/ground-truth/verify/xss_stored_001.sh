#!/usr/bin/env bash
# XSS-STORED-001 (CWE-79): a comment body is stored then rendered by
# post_show.blade.php through the unescaped {!! !!}, executing for every viewer.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
PID=$(post_id acme-welcome)
MARK="<script>xss_$RANDOM$RANDOM</script>"
post "/posts/$PID/comments" --data-urlencode "body=$MARK" >/dev/null
curl -s -b "$JAR" "$TARGET/posts/$PID" | grep -qF "$MARK"
