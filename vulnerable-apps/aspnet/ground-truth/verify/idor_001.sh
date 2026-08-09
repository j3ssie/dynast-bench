#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
GID=$(post_id globex-internal)
curl -s -b "$JAR" "$TARGET/api/posts/$GID" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
