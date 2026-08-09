#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/search" --data-urlencode 'q=<script>GO-XSS-REFLECT</script>' | grep -q '<script>GO-XSS-REFLECT</script>'
