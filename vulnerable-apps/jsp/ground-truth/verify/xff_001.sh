#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -H 'X-Forwarded-For: 127.0.0.1' "$TARGET/internal/admin" | grep -F 'XFF-TRUST-MARKER'
