#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/search?q=%3Cscript%20id%3Daspnet-reflected-xss%3Ealert(1)%3C/script%3E" | grep -q '<script id=aspnet-reflected-xss>'
