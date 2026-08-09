#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
service_token | grep -q .
