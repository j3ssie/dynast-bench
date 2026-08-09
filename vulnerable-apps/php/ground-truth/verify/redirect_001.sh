#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -si "$TARGET/redirect.php?next=https://evil.example/phish" | grep -qi '^Location: https://evil.example/phish'
