#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
q='query($w:JSONObject){ searchPosts(where:$w) { slug body } }'
gql "$q" "$tok" '{"w":{"raw":"OR 1=1 --"}}' | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
