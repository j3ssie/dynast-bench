#!/usr/bin/env bash
# POSTMSG-002 (CWE-79/CWE-95): the Advanced panel's shell bridge compiles the
# expression it is handed with Function(), from any origin. The panel is
# code-split, so the handler does not exist until the button is clicked - hence
# the --click before the message goes out. A fired dialog proves it ran.
set -e; . "$(dirname "$0")/_lib.sh"
M="POSTMSG-DEVTOOLS-PROVEN-7f3a"
JS="window.postMessage({type:'taskflow:devtools',expr:\"alert('$M')\"},'*'); await new Promise(function(r){setTimeout(r,1200);}); return 'sent';"
browser_dialog "$TARGET/profile" "$M" --click '[data-advanced-toggle]' --eval "$JS"
