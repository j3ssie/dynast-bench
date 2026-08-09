#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_state
login user1@bench.local User123!
curl -sf -b "$JAR" -X POST "$TARGET/api/v1/invites" -H 'content-type: application/json' -d '{"email":"neg@bench.local","quantity":-5}' | grep -q '"seatsUsed":-5'
reset_state
