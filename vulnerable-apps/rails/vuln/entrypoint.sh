#!/bin/sh
set -e
echo "[entrypoint] preparing Rails database..."
bundle exec ruby bin/rails db:prepare
echo "[entrypoint] seeding..."
bundle exec ruby bin/rails db:seed || echo "[entrypoint] seed failed (continuing)"
echo "[entrypoint] starting Puma..."
exec bundle exec puma -C config/puma.rb
