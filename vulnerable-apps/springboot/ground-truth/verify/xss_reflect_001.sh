#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS --get "$TARGET/search" --data-urlencode 'q=<script>alert(1)</script>' | grep -q '<script>alert(1)</script>'
