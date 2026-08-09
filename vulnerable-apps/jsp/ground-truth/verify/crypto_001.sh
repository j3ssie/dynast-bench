#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
out=$(curl -sG "$TARGET/crypto" --data-urlencode 'secret=AAAAAAAAAAAAAAAA')
a=$(printf '%s\n' "$out" | sed -n '1p')
b=$(printf '%s\n' "$out" | sed -n '2p')
[ -n "$a" ] && [ "$a" = "$b" ]
