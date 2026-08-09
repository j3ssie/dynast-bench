#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
reset_state
tok=$(login_token user1@bench.local User123!)
gql 'mutation { updateProfile(input:{role:"admin", isAdmin:true}) { role isAdmin } }' "$tok" | grep -q '"isAdmin":true'
