#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
payload='<script>JSP-XSS-MARKER</script>'
curl -sG "$TARGET/reflect.jsp" --data-urlencode "q=$payload" | grep -F "$payload"
