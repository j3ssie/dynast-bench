#!/usr/bin/env bash
# XSS-REFLECT-001: reflected XSS. /search?q= reflects q into HTML unescaped.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/search?q=<script>alert(7)</script>" | grep -q '<script>alert(7)</script>'
