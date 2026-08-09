#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
gql '{ posts { author { email passwordHash resetToken } } }' "$tok" | grep -q 'reset-editor-0e2'
