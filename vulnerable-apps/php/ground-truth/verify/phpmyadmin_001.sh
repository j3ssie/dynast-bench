#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
pma=$(pma_url)
body=$(curl -fsS --max-time 3 "$pma/" || true)
if grep -qi 'phpMyAdmin' <<<"$body"; then
  exit 0
fi
body=$({ curl -s -G --data-urlencode 'url=http://phpmyadmin/' "$TARGET/fetch.php"; curl -s -G --data-urlencode 'url=http://phpmyadmin:8081/' "$TARGET/fetch.php"; } || true)
grep -qi 'phpMyAdmin' <<<"$body"
