#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/actuator/heapdump")" = "200" ]
