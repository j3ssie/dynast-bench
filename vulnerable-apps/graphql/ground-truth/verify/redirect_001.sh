#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
curl -si "$TARGET/auth/callback?next=https://evil.example/path" | grep -qi 'location: https://evil.example/path'
