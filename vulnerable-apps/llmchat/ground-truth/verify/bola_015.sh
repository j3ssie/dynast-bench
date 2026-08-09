#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
get_auth "$TARGET/api/rag/search?collection_id=globex-support&q=policy" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
