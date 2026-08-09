#!/usr/bin/env bash
# IDOR-001 (CWE-639): an Acme user reads a Globex draft by id (no org check).
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
GID=$(post_id globex-internal)
curl -s -b "$JAR" "$TARGET/api/posts/$GID" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
