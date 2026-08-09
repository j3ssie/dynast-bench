#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
pid=$(post_id globex-internal)
login user1@bench.local User123!
out=$(curl -s -b "$JAR" "$TARGET/api/posts/$pid")
echo "$out" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
