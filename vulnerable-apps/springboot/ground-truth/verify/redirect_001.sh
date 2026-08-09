#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
loc=$(curl -s -o /dev/null -D - "$TARGET/goto?next=https://evil.example/phish" | tr -d '' | awk 'tolower($1)=="location:"{print $2}')
[ "$loc" = "https://evil.example/phish" ]
