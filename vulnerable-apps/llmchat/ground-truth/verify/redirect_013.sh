#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
get_auth "$TARGET/api/citations/render?url=https://evil.example/phish" | grep -q 'href="https://evil.example/phish"'
