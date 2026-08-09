#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
p='<script>PHP_REFLECT_XSS</script>'
curl -s -G --data-urlencode "q=$p" "$TARGET/search.php" | grep -q "$p"
