#!/bin/sh
set -eu
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export VARIANT="${VARIANT:-safe}"
export ROLE="${ROLE:-scanner}"
exec node /app/simulator.mjs
