#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/errors/boom" | grep -Eq 'SPRINGBOOT-STACKTRACE-MARKER|java.lang.IllegalStateException|trace'
