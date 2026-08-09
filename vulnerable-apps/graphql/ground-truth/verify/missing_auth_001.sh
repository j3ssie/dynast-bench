#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql 'mutation { deleteOrganization(id:"2") { ok message } }' "$tok" | grep -q '"ok":true'
