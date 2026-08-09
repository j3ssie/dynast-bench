#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/wp-config.php.bak" | grep -q "SECURE_AUTH_KEY='weak-salt'"
