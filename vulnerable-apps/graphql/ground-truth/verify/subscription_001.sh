#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
node "$(dirname "$0")/gqlws.mjs" "$TARGET" "$tok" 2 | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
