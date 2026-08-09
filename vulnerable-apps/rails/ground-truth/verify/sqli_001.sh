#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
q="%' OR body LIKE '%GLOBEX-CONFIDENTIAL-MARKER-7f3a%' --"
out=$(curl -sG "$TARGET/api/posts/search" --data-urlencode "q=$q")
echo "$out" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
