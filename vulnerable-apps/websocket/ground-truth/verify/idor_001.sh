#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
pid=$(post_id globex-internal)
ws_send "$WS_TARGET/ws" --token "$tok" --send "{\"id\":1,\"type\":\"post.get\",\"data\":{\"id\":$pid}}" --expect 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
