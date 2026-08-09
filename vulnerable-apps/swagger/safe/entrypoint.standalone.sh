#!/bin/sh
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in postgres redis mailpit partner-api; do
  grep -q "[[:space:]]$h\$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts
done

export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://bench@postgres:5432/bench}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export PARTNER_URL="${PARTNER_URL:-http://partner-api:9099}"

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

echo "[standalone] starting redis"
redis-server --bind 127.0.0.1 --daemonize yes >/dev/null 2>&1 || true

echo "[standalone] starting internal sinks"
node /app/internal-sink.mjs &

echo "[standalone] applying schema + seed"
python -m app.seed

echo "[standalone] starting Swagger benchmark app"
exec uvicorn app.main:app --host 0.0.0.0 --port 3000
