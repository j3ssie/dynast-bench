#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"subscribe","data":{"channel":"internal:billing"}}' --expect 'INTERNAL-BILLING-LEDGER'
