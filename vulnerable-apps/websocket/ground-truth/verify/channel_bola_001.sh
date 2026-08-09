#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"subscribe","data":{"channel":"org:globex:posts"}}' --expect 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
