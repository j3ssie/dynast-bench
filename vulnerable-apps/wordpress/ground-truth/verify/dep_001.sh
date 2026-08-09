#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/wp-content/plugins/bench-tasks/vendor/vulnerable-lib.js" | grep -q "lodash 4.17.11"
