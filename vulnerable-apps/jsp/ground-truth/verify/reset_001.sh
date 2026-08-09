#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/reset" --data-urlencode 'email=admin@bench.local' | grep -E 'reset token [0-9]+'
