#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/manage/users" | grep -F 'ADMIN-USERS'
