#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
rid=$(gql 'mutation { createReport(name:"%'"'"' OR 1=1 --") { id } }' "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["createReport"]["id"])')
gql "{ reportRun(id:\"$rid\") { result } }" "$tok" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
