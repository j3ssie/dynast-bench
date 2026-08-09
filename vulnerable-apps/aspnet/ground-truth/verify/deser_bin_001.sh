#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
payload=$(curl -s "$TARGET/api/import/binary/sample?message=BINFORMATTER-PWN")
curl -s -X POST "$TARGET/api/import/binary" -H 'content-type: application/json' -d "{\"payload\":\"$payload\"}" | grep -q 'BINFORMATTER-PWN'
