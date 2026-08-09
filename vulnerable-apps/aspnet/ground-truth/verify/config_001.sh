#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/config/client" | grep -q 'BenchPlaintextSecret-aspnet-123'
