#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -sf -b "$JAR" -X POST "$TARGET/api/v1/integrations/fetch" -H 'content-type: application/json' -d '{"url":"http://partner-api:9099/internal/metadata"}' | grep -q 'SWAGGER-PARTNER-INTERNAL'
