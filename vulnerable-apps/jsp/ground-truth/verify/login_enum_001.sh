#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/login" --data-urlencode 'email=enum-nope@bench.local' --data-urlencode 'password=nope' | grep -F 'no such user'
