#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok=$(user_token)
curl -sS "$TARGET/api/health?token=$tok" >/dev/null
curl -sS "$TARGET/api/debug/access-log" | grep -q "$tok"
