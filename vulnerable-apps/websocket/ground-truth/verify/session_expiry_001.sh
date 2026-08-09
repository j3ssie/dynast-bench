#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token 1)
ws_send "$WS_TARGET/ws" --token "$tok" --sleep-before-send-ms 1600 --timeout 3500 --send '{"id":1,"type":"post.get","data":{"id":1}}' --expect 'Acme welcome'
