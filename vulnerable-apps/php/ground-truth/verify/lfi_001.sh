#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode 'page=/etc/hosts' "$TARGET/page.php" | grep -q 'localhost'
