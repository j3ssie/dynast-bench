#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/socket.io/?EIO=4&transport=websocket" --token "$tok" --socketio-admin --expect 'admin namespace secret' --timeout 2500
