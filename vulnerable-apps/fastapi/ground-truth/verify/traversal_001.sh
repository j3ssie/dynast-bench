#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/attachments/download?name=../../secret.txt" | grep -q 'FASTAPI-LOCAL-SECRET-9b4d'
