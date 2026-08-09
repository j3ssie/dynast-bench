#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
q='mutation {'
for i in $(seq 1 30); do q="$q a$i: login(email:\"admin\", password:\"admin\") { token }"; done
q="$q }"
gql "$q" | grep -q 'token'
