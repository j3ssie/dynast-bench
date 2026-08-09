#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"chat.send","data":{"room":"org:acme:posts","from":"admin@bench.local","body":"impersonation-poc"}}' --expect 'admin@bench.local'
curl -sS "$TARGET/api/rooms/org%3Aacme%3Aposts/transcript" | grep -q 'admin@bench.local.*impersonation-poc'
