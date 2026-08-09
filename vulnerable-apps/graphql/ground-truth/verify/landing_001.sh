#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/" | grep -q 'Apollo GraphQL landing page'
