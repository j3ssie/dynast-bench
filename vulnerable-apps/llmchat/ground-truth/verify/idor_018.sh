#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
CID=$(conv_id_by_title 'Globex confidential')
login user1@bench.local User123!
get_auth "$TARGET/api/conversations/$CID" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
