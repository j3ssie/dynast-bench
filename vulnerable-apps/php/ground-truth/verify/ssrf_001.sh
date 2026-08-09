#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode 'url=http://mailpit:8025/' "$TARGET/fetch.php" | grep -Eq 'Mailpit|PHP-INTERNAL-SINK'
