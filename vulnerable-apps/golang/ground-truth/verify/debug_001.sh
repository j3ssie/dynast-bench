#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/debug/pprof/goroutine?debug=1" | grep -q 'goroutine profile'
