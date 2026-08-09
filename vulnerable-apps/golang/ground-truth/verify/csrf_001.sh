#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_acme
login user1@bench.local User123!
body=$(curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'Origin: https://evil.example' -H 'content-type: application/json' -d '{"quantity":1}')
grep -q '"seatsLimit":2' <<<"$body"
