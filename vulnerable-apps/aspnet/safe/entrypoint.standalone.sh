#!/bin/sh
set -e
for h in sqlserver mailpit; do grep -q "[[:space:]]$h$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts; done
export ConnectionStrings__Default="Memory"
export USE_MEMORY_DB="true"
export SMTP_HOST="mailpit"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export ASPNETCORE_URLS="http://+:3000"
node /app/internal-sink.mjs &
exec dotnet /app/BenchAspNet.dll
