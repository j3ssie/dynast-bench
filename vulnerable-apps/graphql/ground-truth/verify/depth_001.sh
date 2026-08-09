#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
q='{ me { organization { posts(first:1) { organization { posts(first:1) { organization { posts(first:1) { organization { posts(first:1) { organization { posts(first:1) { organization { posts(first:1) { id } } } } } } } } } } } } } }'
out=$(gql "$q" "$tok")
echo "$out" | grep -q 'DEPTH_LIMIT' && exit 1
echo "$out" | grep -q '"data"'
