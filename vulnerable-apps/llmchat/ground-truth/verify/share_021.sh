#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/share/1001" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
