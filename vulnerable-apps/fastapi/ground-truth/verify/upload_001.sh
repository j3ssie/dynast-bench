#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
tmp="$(mktemp -d)/evil.svg"   # -d + name keeps the extension on GNU and BSD mktemp
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>FASTAPI_UPLOAD_42</script></svg>' > "$tmp"
resp=$(curl -s -b "$JAR" -F "file=@$tmp;filename=evil.svg;type=image/svg+xml" "$TARGET/api/avatar")
url=$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("url", ""))')
[ -n "$url" ]
curl -s "$TARGET$url" | grep -q 'FASTAPI_UPLOAD_42'
