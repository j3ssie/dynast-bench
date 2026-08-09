#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
name="' OR body LIKE '%GLOBEX-CONFIDENTIAL-MARKER-7f3a%' --"
created=$(curl -s -b "$JAR" -X POST "$TARGET/api/reports" --data-urlencode "name=$name")
rid=$(printf '%s' "$created" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id", ""))')
out=$(curl -s -b "$JAR" "$TARGET/api/reports/$rid/run")
echo "$out" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
