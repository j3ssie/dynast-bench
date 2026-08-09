#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
payload=$'--- !ruby/object:ImportProbe\ntemplate: "<%= 7*7 %>"\n'
out=$(curl -s -X POST "$TARGET/api/import/yaml" --data-urlencode "payload=$payload")
[ "$out" = "49" ]
