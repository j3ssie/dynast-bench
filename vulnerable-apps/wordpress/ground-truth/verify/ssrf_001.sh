#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s --get "$TARGET/wp-json/bench-tasks/v1/fetch" --data-urlencode "url=http://internal-sink:8025/" | grep -q "INTERNAL-SINK"
