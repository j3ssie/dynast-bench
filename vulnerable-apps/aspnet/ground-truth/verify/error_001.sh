#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/debug/crash" | grep -q 'InvalidOperationException'
