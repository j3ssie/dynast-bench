#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
pid=$(post_id acme-welcome)
curl -sf -b "$JAR" -X DELETE "$TARGET/api/v1/posts/$pid" | grep -q 'deleted'
