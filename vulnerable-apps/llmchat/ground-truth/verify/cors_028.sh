#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -i -X OPTIONS "$TARGET/api/chat" -H 'Origin: https://evil.example' -H 'Access-Control-Request-Headers: authorization,content-type' | grep -Eqi 'access-control-allow-origin: https://evil.example'
