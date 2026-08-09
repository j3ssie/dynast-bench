#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
pid=$(post_id globex-internal)
curl -sf -b "$JAR" "$TARGET/api/v1/posts/$pid" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
