#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"chat.send","data":{"room":"org:acme:posts","body":"<script>window.XSS_WS=1</script>"}}' --expect 'XSS_WS'
curl -sS "$TARGET/api/rooms/org%3Aacme%3Aposts/transcript" | grep -q '<script>window.XSS_WS=1</script>'
