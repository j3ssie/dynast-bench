#!/usr/bin/env bash
set -eu; . "$(dirname "$0")/_lib.sh"
s(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/signup/start.php" -H 'content-type: application/json' -d "{\"email\":\"$1\"}"; }
[ "$(s user1@bench.local)" != "$(s "nobody-$$@bench.local")" ]
