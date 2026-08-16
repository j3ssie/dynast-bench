#!/usr/bin/env bash
# Wait for a container to answer its health endpoint.
#
#   wait-healthy.sh <container-name> <health-url> [timeout-seconds]
#
# Used by every app's `make solo` target. The CLI has its own health gate
# (`dynast-bench start --solo`), but `make` has to work without bun, so this is
# the shell equivalent - in one place rather than pasted into 20 Makefiles.
#
# Exits non-zero, with logs, if the container dies or never becomes ready. The
# alternative it replaced was `echo "give it ~30s"`, which reported success
# before the app had started.
set -u

name="${1:?usage: wait-healthy.sh <container> <url> [timeout]}"
url="${2:?usage: wait-healthy.sh <container> <url> [timeout]}"
budget="${3:-180}"

printf '>> waiting for %s' "$name"
deadline=$(( $(date +%s) + budget ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  # --max-time or the deadline below is not a deadline: an app that accepts the
  # connection and then never answers holds curl open indefinitely, and the loop
  # never gets back around to check the clock.
  if curl -sf -o /dev/null --max-time 5 "$url"; then
    echo "  ready"
    exit 0
  fi
  # `--rm` means an exited container disappears, so "gone" is the failure signal
  if ! docker ps -q -f "name=$name" | grep -q .; then
    echo
    echo "!! $name exited early - see: docker logs $name" >&2
    exit 1
  fi
  printf '.'
  sleep 2
done

echo
echo "!! $name never answered $url within ${budget}s" >&2
docker logs --tail 30 "$name" 2>&1 || true
exit 1
