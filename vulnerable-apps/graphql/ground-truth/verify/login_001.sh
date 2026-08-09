#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
gql 'mutation { login(email:"nobody@bench.local", password:"bad") { token } }' | grep -Eq 'USER_NOT_FOUND|nobody@bench.local'
