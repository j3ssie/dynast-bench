#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/crypto/hash?text=password" | grep -q '5f4dcc3b5aa765d61d8327deb882cf99'
