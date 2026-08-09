#!/bin/sh
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in postgres redis billing-svc; do
  grep -q "[[:space:]]$h$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts
done

export DATABASE_URL="${DATABASE_URL:-postgresql://bench:bench@postgres:5432/bench}"
export BILLING_URL="${BILLING_URL:-http://billing-svc:9099}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export PORT="${PORT:-3000}"

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

echo "[standalone] starting internal billing sink (:9099)"
node /app/internal-sink.mjs &

echo "[standalone] starting GraphQL app"
exec node /app/dist/main.js
