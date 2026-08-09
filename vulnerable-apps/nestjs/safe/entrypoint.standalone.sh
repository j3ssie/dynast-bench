#!/bin/sh
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in app postgres redis internal-sink; do
  grep -q "[[:space:]]$h\$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts
done

export DATABASE_URL="${DATABASE_URL:-postgresql://bench@postgres:5432/bench}"
export REDIS_URL="${REDIS_URL:-redis://redis:6379}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"

PGBIN="$(ls -d /usr/lib/postgresql/*/bin | tail -1)"
export PGDATA=/var/lib/pgdata
mkdir -p "$PGDATA" /app/uploads /app/attachments /var/www
chown -R postgres:postgres "$PGDATA"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "[standalone] initdb (trust auth)"
  su postgres -c "$PGBIN/initdb -D $PGDATA -U bench --auth-host=trust --auth-local=trust" >/dev/null
fi

echo "[standalone] starting postgres"
su postgres -c "$PGBIN/pg_ctl -D $PGDATA -o \"-c listen_addresses='127.0.0.1' -p 5432\" -w -t 30 start"
su postgres -c "$PGBIN/createdb -h 127.0.0.1 -U bench bench" 2>/dev/null || true

echo "[standalone] starting redis"
redis-server --daemonize yes --bind 127.0.0.1 --port 6379

echo "[standalone] starting internal sink"
node /app/internal-sink.mjs &

echo "[standalone] preparing nginx"
cp /app/infra/nginx.conf /etc/nginx/conf.d/default.conf
sed -i 's/listen 80;/listen 3000;/' /etc/nginx/conf.d/default.conf
ln -sfn /app/uploads /var/www/uploads
cp /app/infra/nginx-secret.txt /var/www/secret.txt
nginx

echo "[standalone] applying schema + seed"
node dist/seed.js

echo "[standalone] starting NestJS"
exec node dist/main.js
