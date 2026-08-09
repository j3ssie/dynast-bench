#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
payload="<script>JSP-STORED-XSS-$RANDOM</script>"
trap 'curl -s -H "$VT" --get "$TARGET/api/_verify/cleanup-comments" --data-urlencode "body=$payload" >/dev/null 2>&1 || true' EXIT
curl -s -X POST "$TARGET/comments" --data-urlencode "body=$payload" >/dev/null
curl -s "$TARGET/comments.jsp" | grep -F "$payload"
