#!/usr/bin/env sh
set -eu
export LLM_BACKEND="${LLM_BACKEND:-stub}"
exec uvicorn app:app --host 0.0.0.0 --port 3000
