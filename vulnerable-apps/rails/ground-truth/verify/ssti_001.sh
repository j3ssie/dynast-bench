#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -s -X POST "$TARGET/api/preview/inline" --data-urlencode 'tpl=<%= 7*7 %>')
[ "$out" = "49" ]
