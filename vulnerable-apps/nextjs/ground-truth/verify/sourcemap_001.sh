#!/usr/bin/env bash
# SOURCEMAP-001 (CWE-540): production browser source maps are published, so every
# chunk has a fetchable *.js.map carrying the original TypeScript in
# `sourcesContent` — original file paths, comments and all.
set -e; . "$(dirname "$0")/_lib.sh"

for c in $(chunk_urls /integrations); do
  map=$(curl -sf "$TARGET$c.map") || continue
  # A real map with inlined original sources, and it is OUR TypeScript.
  printf '%s' "$map" | grep -q '"sourcesContent"' || continue
  printf '%s' "$map" | grep -q 'webpack://.*src/.*\.tsx\?' || continue
  exit 0
done
exit 1
