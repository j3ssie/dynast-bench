#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(login user1@bench.local User123!)
rid=$(start_run "$tok" "AUTONOMY_LOOP")
verify_run "$rid" | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{let n=(s.match(/\"tool\":\"delegate\"/g)||[]).length;process.exit(n>100?0:1)})"
