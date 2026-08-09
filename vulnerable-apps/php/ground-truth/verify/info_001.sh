#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
body=$(curl -s "$TARGET/info.php" || true)
grep -qi 'PHP Version' <<<"$body"
