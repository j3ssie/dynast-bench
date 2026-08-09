#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_acme
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"quantity":-5}' | grep -q '"seatsLimit":-4'
