#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s -X POST "$TARGET/api/webhooks/test" -H 'content-type: application/json' -d '{"url":"http://internal-sink:8025/"}')
grep -q 'NESTJS-INTERNAL-SINK' <<<"$body"
