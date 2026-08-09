#!/usr/bin/env bash
# XSS-REFLECT-002 (CWE-79): the q param is reflected unescaped into the search page.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/posts/search?q=<script>alert(1)</script>" | grep -q '<script>alert(1)</script>'
