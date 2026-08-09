#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/stream" -d '{"title":"<img src=x onerror=alert(9)>"}' | grep -q '<img src=x onerror=alert(9)>'
