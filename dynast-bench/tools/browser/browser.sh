# Headless-browser helpers for the ground-truth PoCs.  Source from an app's _lib.sh.
#
# Most PoCs are curl and must stay that way. These are for the handful of bugs
# whose sink only exists once the page's own JavaScript has run - DOM XSS,
# postMessage handlers, client-side routing - where a request/response transcript
# cannot tell you whether anything actually executed.
#
#   browser_require                     build/pull the image, or fail loudly
#   browser <url> [drive.mjs flags...]  drive the page, print the JSON probe
#   browser_dialog <url> <marker> [...] exit 0 if a JS dialog carrying <marker> fired
#   browser_requested <url> <substr> [...] exit 0 if the page requested a matching URL
#
# The URL a PoC passes is always a host URL ($TARGET). Reaching it from inside a
# container is the one genuinely non-portable part: the apps bind 127.0.0.1 only,
# which on Linux is unreachable from a bridge network, so there the run joins the
# host's own namespace. Docker Desktop cannot do that reliably, but does route
# host.docker.internal back to the host's loopback, so elsewhere the URL is
# rewritten instead. Both paths are verified against a live 127.0.0.1 bind.

DYNAST_BROWSER_IMAGE="${DYNAST_BROWSER_IMAGE:-dynast-bench-browser:1}"

# Where this file lives, so the build context is findable no matter which app's
# verify/ directory the PoC was launched from.
DYNAST_BROWSER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolved once at source time: every PoC in a run gets the same answer, and
# `browser` is called often enough that a fork per call is worth avoiding.
_DYNAST_HOST_OS="$(uname -s)"

browser_available() {
  docker image inspect "$DYNAST_BROWSER_IMAGE" >/dev/null 2>&1
}

# Build the image if it is not there yet. Safe to call repeatedly and from
# several PoCs at once - docker serialises the build and the second caller hits
# the layer cache. run.sh calls this once up front, so the common case is the
# memo below rather than a `docker image inspect` per browser call.
browser_require() {
  [ -n "${_DYNAST_BROWSER_OK:-}" ] && return 0
  command -v docker >/dev/null 2>&1 || {
    echo "browser PoC needs docker, which is not on PATH" >&2
    return 2
  }
  if ! browser_available; then
    echo ">> building $DYNAST_BROWSER_IMAGE (first browser PoC - one time, ~1GB pull)" >&2
    docker build -q -t "$DYNAST_BROWSER_IMAGE" "$DYNAST_BROWSER_DIR" >/dev/null || {
      echo "browser image failed to build - browser PoCs cannot run" >&2
      return 2
    }
  fi
  # exported so the per-PoC shells the runner spawns inherit the answer instead
  # of each paying a `docker image inspect`
  export _DYNAST_BROWSER_OK=1
}

_browser_net() {
  if [ "$_DYNAST_HOST_OS" = "Linux" ]; then
    echo "--network=host"
  else
    echo "--add-host=host.docker.internal:host-gateway"
  fi
}

_browser_url() {
  if [ "$_DYNAST_HOST_OS" = "Linux" ]; then
    printf '%s' "$1"
  else
    # Only the host part moves; the port, path and fragment have to survive
    # intact, so capture the delimiter that follows rather than swallowing it.
    printf '%s' "$1" | sed -E 's#//(127\.0\.0\.1|localhost)(:|/|$)#//host.docker.internal\2#'
  fi
}

# Chromium is the one container in the suite that is NOT the app under test, and
# it was the only one with no ceiling: a renderer fed a hostile page (which is
# exactly what a DOM-XSS PoC feeds it) can take the docker VM down and every
# other app on the daemon with it. --init also matters more here than anywhere -
# chrome forks a zombie-prone tree of zygote/renderer/gpu processes.
_browser_limits() {
  echo "--memory=1g --cpus=2 --pids-limit=512 --init --log-opt max-size=5m"
}

browser() {
  browser_require || return 2
  local url="$1" rc
  shift
  # shellcheck disable=SC2046  # the flags are separate words and must not be quoted
  docker run --rm $(_browser_net) $(_browser_limits) "$DYNAST_BROWSER_IMAGE" \
    --url "$(_browser_url "$url")" "$@"
  rc=$?
  # drive.mjs uses its exit code ONLY for "the probe itself could not run" -
  # whether the page was vulnerable is decided by grepping the JSON below. So any
  # nonzero (chromium failed to launch, navigation failed, `docker run` itself
  # errored with 125) is a harness result, never "not exploitable". Collapsing
  # them to 2 is what stops the runner reading a broken probe as "fixed".
  [ "$rc" -eq 0 ] || return 2
}

# Proof that injected script EXECUTED: a dialog whose text carries our marker.
# Reflection alone never fires one. Markers are matched literally (-F) because a
# payload is exactly the kind of string that is also a regex.
#
# Both helpers capture the probe before grepping it: in a pipeline the status is
# the trailing grep's, which would turn "the harness could not run" (exit 2) into
# "not exploitable" (exit 1) - a wrong answer about the app rather than about us.
browser_dialog() {
  local url="$1" marker="$2" out
  shift 2
  # --until lets the probe stop settling the moment the dialog fires. On the safe
  # twin nothing fires and it waits the full budget, which is the point: proving
  # the absence of execution is exactly the case you must not short-circuit.
  out="$(browser "$url" --until "dialog:$marker" "$@")" || return $?
  printf '%s' "$out" | grep '"message":' | grep -qF "$marker"
}

# Proof that a route is only discoverable by running the page: the browser asked
# for it, but it appears nowhere in the served HTML.
browser_requested() {
  local url="$1" want="$2" out
  shift 2
  out="$(browser "$url" --until "request:$want" "$@")" || return $?
  printf '%s' "$out" | grep -E '"[A-Z]+ https?://' | grep -qF "$want"
}
