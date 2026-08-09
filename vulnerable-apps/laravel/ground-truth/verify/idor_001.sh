#!/usr/bin/env bash
# IDOR-001 (CWE-639): an Acme user reads a Globex draft by id (route-model
# binding with no owner/org/status check).
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
GID=$(post_id globex-internal)
curl -s -b "$JAR" "$TARGET/posts/$GID" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
