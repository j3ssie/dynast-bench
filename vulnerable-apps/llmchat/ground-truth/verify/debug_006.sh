#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
get_auth "$TARGET/api/chat/config" | grep -Eq 'service_credential|system_prompt|admin/admin'
