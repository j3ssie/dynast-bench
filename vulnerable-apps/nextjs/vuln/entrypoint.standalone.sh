#!/bin/sh
# All-in-one entrypoint: starts Postgres + Redis + an internal SSRF sink inside
# this single container, then the app. The /etc/hosts aliases make the compose
# service names resolve to localhost, so the app config, env, and every PoC are
# byte-identical to the multi-container topology.
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in postgres redis mailpit; do
  grep -q "[[:space:]]$h\$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts
done

# Runtime env (the build used a dummy DATABASE_URL). These match the compose file.
export DATABASE_URL="postgresql://bench@postgres:5432/bench"
export REDIS_URL="redis://redis:6379"
export SMTP_HOST="mailpit"
export APP_URL="http://localhost:3000"
export JWT_SECRET="${JWT_SECRET:-dev-super-secret-change-me}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"

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
redis-server --daemonize yes --bind 127.0.0.1 --port 6379 >/dev/null

echo "[standalone] starting internal SSRF sink (:8025)"
node /app/internal-sink.mjs &

echo "[standalone] applying schema + seed"
npx prisma db push --skip-generate --accept-data-loss
node prisma/seed.mjs || echo "[standalone] seed failed (continuing)"

echo "[standalone] starting Next.js"
exec npm run start
