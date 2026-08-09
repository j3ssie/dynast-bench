#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql "{ posts(filter:\"%' OR 1=1 --\", first:20) { slug body } }" "$tok" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
