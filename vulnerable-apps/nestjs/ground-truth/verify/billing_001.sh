#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"delta":-999}' >/dev/null
seats=$(org_field acme seatsUsed)
curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"delta":999}' >/dev/null || true
[ "$seats" -lt 0 ]
