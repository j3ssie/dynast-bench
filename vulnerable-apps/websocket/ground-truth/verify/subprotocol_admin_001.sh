#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ws_send "$WS_TARGET/ws" --protocol admin-v1 --send '{"id":1,"type":"admin.userDelete","data":{"userId":4}}' --expect 'deletedUserId'
