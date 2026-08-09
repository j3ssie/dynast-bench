#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql '{ posts(orderBy:"not_a_column"){ id } }' "$tok" | grep -Eq 'stack|not_a_column|sql'
