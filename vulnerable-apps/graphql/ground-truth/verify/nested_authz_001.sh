#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql '{ me { organization { posts { slug body } } } }' "$tok" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
