#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
get_auth -X POST "$TARGET/api/summarize/c-acme-1" | grep -q '"depth":8'
