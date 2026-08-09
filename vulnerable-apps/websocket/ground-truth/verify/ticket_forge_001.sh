#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(node -e "console.log(Buffer.from('1:' + (Math.floor(Date.now()/1000)+3600) + ':admin').toString('base64url'))")
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"admin.userDelete","data":{"userId":4}}' --expect 'deletedUserId'
