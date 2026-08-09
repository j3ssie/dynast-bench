#!/bin/sh
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in postgres internal-sink; do
  grep -q "[[:space:]]$h\$" /etc/hosts 2>/dev/null || printf '127.0.0.1 %s\n' "$h" >> /etc/hosts
done

export DATABASE_URL="postgres://bench@postgres:5432/bench"
export SECRET_KEY_BASE="${SECRET_KEY_BASE:-safe-rails-runtime-secret-from-standalone-111111111111111111111111}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export INTERNAL_SINK_URL="${INTERNAL_SINK_URL:-http://internal-sink:8025/metadata}"

PGBIN="$(ls -d /usr/lib/postgresql/*/bin | tail -1)"
export PGDATA=/var/lib/pgdata
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "[standalone] initdb (trust auth)"
  su postgres -c "$PGBIN/initdb -D $PGDATA -U bench --auth-host=trust --auth-local=trust" >/dev/null
fi

echo "[standalone] starting postgres"
su postgres -c "$PGBIN/pg_ctl -D $PGDATA -o \"-c listen_addresses='127.0.0.1' -p 5432\" -w -t 30 start"
su postgres -c "$PGBIN/createdb -h 127.0.0.1 -U bench bench" 2>/dev/null || true

echo "[standalone] starting internal SSRF sink (:8025)"
ruby /app/internal-sink.rb &

echo "[standalone] preparing schema + seed"
bundle exec ruby bin/rails db:prepare
bundle exec ruby bin/rails db:seed || echo "[standalone] seed failed (continuing)"

echo "[standalone] starting Puma"
exec bundle exec puma -C config/puma.rb
