#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sf -X POST "$TARGET/api/v1/reports" -H 'content-type: application/json' -d '{"name":"anon-report","queryFilter":"published"}' | grep -q 'anon-report'
