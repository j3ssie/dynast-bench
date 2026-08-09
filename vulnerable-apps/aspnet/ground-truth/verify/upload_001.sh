#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
tmp=$(mktemp); printf '<%% Response.Write("UPLOAD-ASPX") %%>' > "$tmp"
curl -s -X POST "$TARGET/api/upload/avatar" -F "file=@$tmp;filename=shell.aspx" | grep -q 'uploaded'
