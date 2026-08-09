#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -i -X POST "$TARGET/login" --data-urlencode 'email=user2@bench.local' --data-urlencode 'password=User123!' --data-urlencode 'next=https://example.com/phish' | grep -Fi 'Location: https://example.com/phish'
