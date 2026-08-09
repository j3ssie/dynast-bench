#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/wp-json/bench-tasks/v1/billing" -d "seats=-5" | grep -q "\"billing_seats\":-5"
