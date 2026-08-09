#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_state
login user1@bench.local User123!
curl -sf -b "$JAR" -X POST "$TARGET/api/v1/integrations/partner/sync?role=admin" -H 'content-type: application/json' -d '{}' | grep -q 'admin'
[ "$(user_role user1@bench.local)" = "admin" ]
reset_state
