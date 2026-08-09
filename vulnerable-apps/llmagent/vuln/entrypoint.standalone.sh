#!/usr/bin/env sh
set -eu
for h in postgres redis ollama partner-mcp internal-svc; do echo "127.0.0.1 $h" >> /etc/hosts; done
node /app/internal-sink.mjs &
exec node src/app.mjs
