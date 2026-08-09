#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/fetch?url=http://mailpit:8025" | grep -Eq 'Mailpit|mailpit|FASTAPI-INTERNAL-SINK'
