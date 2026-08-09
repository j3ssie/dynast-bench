#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
email=$'evil@bench.local\nadmin@bench.local'
out=$(curl -s -X POST "$TARGET/api/admin/check_email" --data-urlencode "email=$email")
echo "$out" | grep -q '"allowed":true'
