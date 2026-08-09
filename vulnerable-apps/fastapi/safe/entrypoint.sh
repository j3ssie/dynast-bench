#!/bin/sh
set -e

python -m app.seed
exec uvicorn app.main:app --host 0.0.0.0 --port 3000
