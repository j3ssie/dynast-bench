#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -I "$TARGET/?author=1" | tr -d "\r" | grep -qi "^Location: /author/admin"
