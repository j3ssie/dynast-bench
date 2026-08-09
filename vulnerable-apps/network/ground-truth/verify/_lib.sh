#!/usr/bin/env bash
# Shared helpers for network ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
set -u
TARGET="${TARGET:-http://127.0.0.1:13311}"
VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
MARKER="GLOBEX-CONFIDENTIAL-MARKER-7f3a"

probe_json() {
  local check="$1"
  curl -fsS -H "X-Verify-Token: ${VERIFY_TOKEN}" "$TARGET/api/_verify/probe?check=${check}"
}

expect_vulnerable() {
  local check="$1"
  local body
  body="$(probe_json "$check")" || return 1
  case "$body" in *'"vulnerable": true'*) return 0;; *) return 1;; esac
}

expect_marker() {
  local check="$1"
  local body
  body="$(probe_json "$check")" || return 1
  case "$body" in *'"vulnerable": true'*"$MARKER"*) return 0;; *) return 1;; esac
}
