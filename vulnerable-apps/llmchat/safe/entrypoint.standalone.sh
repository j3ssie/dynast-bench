#!/usr/bin/env sh
set -eu
for h in postgres redis ollama internal-svc; do
  if ! grep -q " $h\$" /etc/hosts 2>/dev/null; then echo "127.0.0.1 $h" >> /etc/hosts || true; fi
done
node /app/internal-sink.mjs >/tmp/llmchat-internal.log 2>&1 &
export LLM_BACKEND="${LLM_BACKEND:-stub}"
exec uvicorn app:app --host 0.0.0.0 --port 3000
