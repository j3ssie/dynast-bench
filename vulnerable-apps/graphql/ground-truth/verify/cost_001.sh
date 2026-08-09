#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
out=$(gql '{ posts(first:9999){ id title } }' "$tok")
echo "$out" | grep -q 'COST_LIMIT' && exit 1
echo "$out" | grep -q 'Welcome Acme'
