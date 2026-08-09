#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
get_auth "$TARGET/api/documents/d-acme-handbook/raw?path=../secrets/service-creds.txt" | grep -q 'LLM_INTERNAL_SECRET_FILE'
