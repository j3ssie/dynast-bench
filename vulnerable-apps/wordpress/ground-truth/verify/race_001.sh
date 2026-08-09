#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_state
curl -s -X POST "$TARGET/wp-json/bench-tasks/v1/invite" -d "slots=5" | grep -q "\"seats_used\":6"
