#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -sf "$TARGET/api/schema/")
printf '%s' "$body" | grep -q 'SWAGGER-INTERNAL-TOKEN-9c21'
printf '%s' "$body" | grep -q 'partner-api:9099'
