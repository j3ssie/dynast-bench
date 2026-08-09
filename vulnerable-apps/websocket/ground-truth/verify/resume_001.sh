#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
ws_send "$WS_TARGET/ws" --token "$tok" --send '{"id":1,"type":"session.save","data":{"sid":"resume-poc"}}' --expect 'resume-poc'
ws_send "$WS_TARGET/ws?sid=resume-poc" --send '{"id":2,"type":"post.get","data":{"id":1}}' --expect 'Acme welcome'
