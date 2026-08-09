#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
file=$(mktemp /tmp/rails-upload-XXXX.svg)
trap 'rm -f "$file"' EXIT
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>window.RAILS_UPLOAD_XSS_611d=1</script></svg>' > "$file"
out=$(curl -s -b "$JAR" -F "file=@$file;filename=rails-upload-611d.svg;type=image/svg+xml" "$TARGET/api/uploads")
echo "$out" | grep -q '/uploads/rails-upload-611d.svg'
curl -s "$TARGET/uploads/rails-upload-611d.svg" | grep -q 'RAILS_UPLOAD_XSS_611d'
