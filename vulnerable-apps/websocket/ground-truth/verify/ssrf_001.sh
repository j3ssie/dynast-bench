#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"webhook.test","data":{"url":"http://internal-svc:9099/secret"}}' --expect 'INTERNAL-SERVICE-SECRET' --timeout 3000
