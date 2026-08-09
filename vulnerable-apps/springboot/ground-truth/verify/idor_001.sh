#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
gid=$(post_id globex-internal)
login user1@bench.local User123! >/dev/null
curl -fsS -b "$JAR" "$TARGET/api/posts/$gid" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
