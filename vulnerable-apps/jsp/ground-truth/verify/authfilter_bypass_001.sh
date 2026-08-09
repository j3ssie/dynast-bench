#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s --path-as-is "$TARGET/admin;public/users" | grep -F 'ADMIN-USERS'
