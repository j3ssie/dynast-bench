#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token admin@bench.local Admin123!)
python3 - "$tok" <<'PY' | gql_raw --data-binary @- | python3 -c 'import json,sys; data=json.load(sys.stdin); s=str(data); sys.exit(0 if s.count("admin@bench.local") >= 2 else 1)'
import json,sys
q='{ users { email } }'
print(json.dumps([{"query":q,"extensions":{"authorization":"Bearer "+sys.argv[1]}},{"query":q}]))
PY
