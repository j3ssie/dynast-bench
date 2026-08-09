#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
pid=$(post_id globex-draft)
global=$(gid "Post:$pid")
gql "{ node(id:\"$global\") }" "$tok" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
