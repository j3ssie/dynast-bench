#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
resp=$(curl -isS --http1.1 --max-time 2 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: http://evil.local' -H "Cookie: ws_ticket=$tok" "$TARGET/ws" || true)
printf '%s' "$resp" | grep -q '101 Switching Protocols'
