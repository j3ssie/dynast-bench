#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"post.search","data":{"q":"x%'"'"' OR 1=1--"}}' --expect 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
