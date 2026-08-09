#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
trap 'curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset-acme" >/dev/null || true' EXIT
login user1@bench.local User123!
resp=$(curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"quantity":-99}')
printf '%s' "$resp" | grep -q '"seatsLimit":-96'
