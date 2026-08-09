#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"billing.seats","data":{"quantity":-5}}' --send '{"id":2,"type":"billing.reset","data":{"used":4}}' --expect '"used":-5'
