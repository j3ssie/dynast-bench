#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql 'mutation { exportReport(format:"csv; echo CMD-INJECTION-OK") }' "$tok" | grep -q 'CMD-INJECTION-OK'
