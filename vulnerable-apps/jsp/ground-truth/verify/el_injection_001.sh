#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/report" --data-urlencode 'mode=el' --data-urlencode 'expr=secret' | grep -F 'EL-INJECTION-MARKER-jsp'
