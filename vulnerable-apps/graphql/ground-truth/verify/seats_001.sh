#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
reset_state
tok=$(login_token user1@bench.local User123!)
gql 'mutation { purchaseSeats(quantity:-5) { ok message } }' "$tok" | grep -q '"ok":true'
