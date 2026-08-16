#!/usr/bin/env bash
# Start a standalone (`make solo`) image with the same containment compose gets.
#
#   solo-run.sh <image> <compose-file> -p 127.0.0.1:13311:3000 [-p ...]
#
# WHY THIS EXISTS
#
# Every compose service in the suite carries mem_limit/cpus/pids_limit (see
# "Resource limits" in CLAUDE.md) - and `make solo` had none of it. A solo image
# embeds every datastore the compose stack ran as its own service, so it is if
# anything the one that most needs a ceiling: several apps plant deliberate
# resource-exhaustion bugs (gin's uncapped gzip bomb, graphql and websocket's
# CWE-770s) and several more spawn a process per request. Uncapped, a scanner
# fuzzing any of those exhausts the docker VM and every other app on the daemon
# dies with it - which reads as "the benchmark is flaky" rather than "gin has a
# DoS". Capped, the same event is one container hitting its ceiling.
#
# The ceiling is the SUM of what the compose stack it replaces was allowed to
# use: the container does all the work the stack did, so copying only the app
# service's limit would under-provision it. Derived from the compose file rather
# than written per app, so it cannot drift - `dynast-bench start --solo` does the
# same arithmetic in soloLimits().
set -eu

img="${1:?usage: solo-run.sh <image> <compose-file> [docker run flags...]}"
compose="${2:?usage: solo-run.sh <image> <compose-file> [docker run flags...]}"
shift 2

# mem_limit / cpus / pids_limit summed across every service in the file.
read -r mem_mb cpus pids <<EOF
$(awk '
  /^[[:space:]]+mem_limit:[[:space:]]*/ {
    v = $2
    n = v + 0
    if (v ~ /[gG]/) n *= 1024; else if (v ~ /[kK]/) n /= 1024
    else if (v !~ /[mM]/) n /= 1048576      # bare bytes
    mem += n
  }
  /^[[:space:]]+cpus:[[:space:]]*/       { cpu  += $2 }
  /^[[:space:]]+pids_limit:[[:space:]]*/ { pids += $2 }
  END { printf "%d %.1f %d\n", (mem ? mem : 2048), (cpu ? cpu : 4), (pids ? pids : 2048) }
' "$compose")
EOF

# docker REFUSES --cpus above the VM's CPU count ("Range of CPUs is from 0.01 to
# N.00"), and a --memory above the VM's RAM is not a ceiling at all - the
# container could still take the daemon down. Clamp to what is actually there.
host_cpus="$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 0)"
host_mem_mb="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
case "$host_cpus" in ''|*[!0-9]*) host_cpus=0 ;; esac
case "$host_mem_mb" in ''|*[!0-9]*) host_mem_mb=0 ;; *) host_mem_mb=$(( host_mem_mb / 1048576 )) ;; esac

if [ "$host_cpus" -gt 0 ]; then
  cpus="$(awk -v a="$cpus" -v b="$host_cpus" 'BEGIN{printf "%.1f", (a<b?a:b)}')"
fi
if [ "$host_mem_mb" -gt 0 ]; then
  ceil=$(( host_mem_mb * 8 / 10 ))
  [ "$mem_mb" -gt "$ceil" ] && mem_mb="$ceil"
fi

echo ">> $img: mem ${mem_mb}m · cpus ${cpus} · pids ${pids}"
exec docker run -d --rm \
  --memory "${mem_mb}m" \
  --cpus "$cpus" \
  --pids-limit "$pids" \
  `# solo entrypoints background postgres/redis/the app and wait; without an` \
  `# init those children reparent to a shell that does not reap them` \
  --init \
  `# json-file has no default cap, and an app logging per request under a` \
  `# scanner fills the daemon's disk` \
  --log-opt max-size=10m --log-opt max-file=3 \
  "$@" \
  --name "$img" "$img"
