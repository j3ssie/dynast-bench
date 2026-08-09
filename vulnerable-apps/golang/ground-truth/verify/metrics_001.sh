#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s "$TARGET/metrics" | grep -q 'user1@bench.local'
