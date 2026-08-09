#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -u admin:admin "$TARGET/manager/html" | grep -F 'TOMCAT-MANAGER-WEAK-SURFACE'
