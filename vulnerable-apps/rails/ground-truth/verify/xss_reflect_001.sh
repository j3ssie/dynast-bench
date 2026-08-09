#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
marker='<img src=x onerror="window.RAILS_REFLECT_XSS_69d1=1">'
out=$(curl -sG "$TARGET/posts/search" --data-urlencode "q=$marker")
echo "$out" | grep -q "$marker"
