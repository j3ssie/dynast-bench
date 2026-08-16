# Shared helpers for the weirdproxy ground-truth PoCs.
# Each PoC exits 0 if the proxy ACL is BYPASSED (marker leaks) — PASS on vuln/,
# FAIL on safe/. $TARGET is the app-under-test (nginx). Apache and Traefik sit on
# the next two sidecar ports; override with WEIRDPROXY_APACHE / WEIRDPROXY_TRAEFIK.
TARGET="${TARGET:-http://127.0.0.1:13311}"
MARKER='GLOBEX-CONFIDENTIAL-MARKER-7f3a'

HOST=$(python3 - "$TARGET" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1])
print(f"{u.scheme or 'http'} {u.hostname or '127.0.0.1'}")
PY
)
SCHEME="${HOST%% *}"; HOSTNAME="${HOST##* }"
NGINX="$TARGET"
# The runner exports the ports the stack actually published; the compose
# defaults are only the fallback for a bare `make verify`. Hardcoding them meant
# every `dynast-bench validate` dialled another app's port and reported all 11
# Apache/Traefik bugs as not exploitable.
# Three layers, narrowest first:
#   DYNAST_PORT_<SERVICE>_80   compose - the runner reads it back off docker
#   DYNAST_SOLO_PORT_808x      solo - one container, no compose service label, so
#                              the publishes are named by the port EXPOSE gave them
#   13312 / 13313              the compose defaults, for a bare `make verify`
APACHE="${WEIRDPROXY_APACHE:-$SCHEME://$HOSTNAME:${DYNAST_PORT_APACHE_80:-${DYNAST_SOLO_PORT_8081:-13312}}}"
TRAEFIK="${WEIRDPROXY_TRAEFIK:-$SCHEME://$HOSTNAME:${DYNAST_PORT_TRAEFIK_80:-${DYNAST_SOLO_PORT_8082:-13313}}}"

# leak <base> <raw-path> [extra-header]
# --path-as-is keeps curl from collapsing //, /./, .. before the request is sent.
leak() {
  local base="$1" path="$2" hdr="${3:-}"
  if [ -n "$hdr" ]; then
    curl -s --path-as-is "$base$path" -H "$hdr" | grep -q "$MARKER"
  else
    curl -s --path-as-is "$base$path" | grep -q "$MARKER"
  fi
}
