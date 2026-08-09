#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/error-demo" | grep -E 'STACKTRACE-MARKER-jsp|RuntimeException'
