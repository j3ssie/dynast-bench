#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/error" | grep -q 'hardcoded-weak-secret'
