#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/wp-json/bench-tasks/v1/task?id=101%20OR%201=1" | contains_marker
