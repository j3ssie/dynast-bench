#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/reports/render" -H 'content-type: application/json' -d '{"template":"{{7*7}}","user":"bench"}' | grep -q '^49$'
