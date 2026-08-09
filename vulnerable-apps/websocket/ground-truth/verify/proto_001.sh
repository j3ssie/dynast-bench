#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"presence.update","data":{"profile":{"__proto__":{"polluted":"PROTO-POLLUTED"}}}}' --send '{"id":2,"type":"proto.check","data":{}}' --send '{"id":3,"type":"proto.cleanup","data":{}}' --expect 'PROTO-POLLUTED'
