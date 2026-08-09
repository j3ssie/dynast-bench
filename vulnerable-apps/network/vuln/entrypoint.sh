#!/bin/sh
set -eu
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export VARIANT="${VARIANT:-vuln}"
export ROLE="${ROLE:-scanner}"
exec node /app/simulator.mjs
