#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS -X POST "$TARGET/api/billing/seats" -H "$json_ct" -d '{"seats":-5}' | grep -q '"seats":-5'
