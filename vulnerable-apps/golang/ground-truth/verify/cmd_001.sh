#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/reports/export" -H 'content-type: application/json' -d '{"name":"monthly; printf $((41+1))"}' | grep -q '^42$'
