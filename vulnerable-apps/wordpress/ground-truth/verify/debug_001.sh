#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/wp-content/debug.log" | grep -q "WP_DEBUG_DISPLAY enabled"
