#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
pid=$(post_id globex-internal)
[ -n "$pid" ]
curl -s -b "$JAR" "$TARGET/posts.php?id=$pid" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
