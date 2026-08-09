#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
gql_raw --data-binary '[{"query":"{ __typename }"},{"query":"{ __typename }"}]' | grep -q '^\['
