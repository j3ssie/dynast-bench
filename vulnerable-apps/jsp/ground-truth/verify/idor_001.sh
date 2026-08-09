#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login 'user1@bench.local' 'User123!'
id=$(post_id globex-draft)
curl -s -b "$JAR" "$TARGET/post?id=$id" | grep -F 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
