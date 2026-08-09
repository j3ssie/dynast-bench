#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
payload='<script>window.NEST_XSS_REFLECT=1</script>'
body=$(curl -s --get "$TARGET/search" --data-urlencode "q=$payload")
grep -Fq "$payload" <<<"$body"
