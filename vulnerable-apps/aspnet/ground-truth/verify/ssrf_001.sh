#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/fetch?url=http://mailpit:8025/" | grep -q 'Mailpit'
