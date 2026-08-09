#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
out=$(curl -fsS -i -H "Origin: http://evil.local" -H "content-type: application/json" -H "authorization: Bearer $tok" -X POST -d '{"prompt":"csrf"}' "$TARGET/api/runs")
printf "%s" "$out" | contains_http "access-control-allow-origin: http://evil.local" && printf "%s" "$out" | contains_http "HTTP/1.1 201"
