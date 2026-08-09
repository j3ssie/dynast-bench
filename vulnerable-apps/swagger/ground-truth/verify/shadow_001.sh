#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sf "$TARGET/api/v1/internal/debug/config" | grep -q 'SECRET_KEY'
