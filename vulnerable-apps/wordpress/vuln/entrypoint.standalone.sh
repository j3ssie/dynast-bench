#!/bin/sh
set -eu
for h in mysql mailpit internal-sink; do
  if ! grep -q " $h$" /etc/hosts; then printf '127.0.0.1 %s\n' "$h" >> /etc/hosts; fi
done
rm -f "/tmp/benchpress-state-${VARIANT:-vuln}.json"
node /app/internal-sink.mjs &
exec php -S 0.0.0.0:3000 -t /app/public /app/public/index.php
