#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
a=$(curl -s "$TARGET/captcha")
b=$(curl -s "$TARGET/captcha")
[ -n "$a" ] && [ "$a" = "$b" ]
