#!/usr/bin/env bash
# REDIRECT-001: open redirect. /goto?next= trusts an absolute external URL.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
loc=$(curl -s -o /dev/null -D - "$TARGET/goto?next=https://evil.example/" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
[ "$loc" = "https://evil.example/" ]
