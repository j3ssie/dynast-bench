#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -isS "$TARGET/socket.io/?EIO=4&transport=polling&t=bench" | grep -q 'sid'
