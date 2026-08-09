#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
gql 'mutation { login(email:"admin", password:"admin") { token } }' | grep -q 'token'
