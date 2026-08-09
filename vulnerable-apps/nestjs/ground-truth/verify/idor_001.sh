#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
id=$(post_id globex-internal)
login user1@bench.local User123!
body=$(curl -s -b "$JAR" "$TARGET/api/posts/$id")
grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a' <<<"$body"
