#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
out=$(curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" --data-urlencode 'seats=-5')
echo "$out" | grep -q '"seatLimit":-5'
# Restore a sane value for order independence; ignored on safe.
curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" --data-urlencode 'seats=2' >/dev/null || true
