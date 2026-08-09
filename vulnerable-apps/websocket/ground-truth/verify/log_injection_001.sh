#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
out=$(ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"presence.update","data":{"profile":{"name":"bob\nrole=admin LOGFORGED"}}}' --send '{"id":2,"type":"audit.tail","data":{}}' --expect 'LOGFORGED')
printf '%s' "$out" | grep -q 'bob\\nrole=admin LOGFORGED'
