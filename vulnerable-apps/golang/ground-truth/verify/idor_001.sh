#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_acme
login user1@bench.local User123!
pid=$(post_id globex-internal)
curl -s -b "$JAR" "$TARGET/api/posts/$pid" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
