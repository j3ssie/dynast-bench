#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
trap 'curl -s -H "$VT" "$TARGET/api/_verify/reset-billing" >/dev/null 2>&1 || true' EXIT
login 'user2@bench.local' 'User123!'
curl -s -b "$JAR" -X POST "$TARGET/billing/seats" --data-urlencode 'seats=-100' | grep -E 'seats=-'
