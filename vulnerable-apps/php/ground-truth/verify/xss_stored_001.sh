#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
pid=$(post_id acme-welcome)
p="<script>PHP_STORED_XSS_$$</script>"
curl -s -b "$JAR" -X POST "$TARGET/comments.php" -d "post_id=$pid" --data-urlencode "body=$p" >/dev/null
curl -s "$TARGET/comments.php?post_id=$pid" | grep -q "$p"
