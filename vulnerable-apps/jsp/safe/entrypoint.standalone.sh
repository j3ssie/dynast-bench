#!/usr/bin/env sh
set -eu
for h in postgres mailpit internal-sink; do grep -q "[[:space:]]$h$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts; done
printf 'XXE-LOCAL-FILE-MARKER-jsp-42\n' > /tmp/jsp-xxe-secret.txt
PGBIN="$(ls -d /usr/lib/postgresql/*/bin | tail -1)"
PGDATA=/var/lib/pgdata
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  su postgres -c "$PGBIN/initdb -D $PGDATA -U bench --auth-host=trust --auth-local=trust" >/dev/null
fi
su postgres -c "$PGBIN/pg_ctl -D $PGDATA -o \"-c listen_addresses='127.0.0.1' -p 5432 -c fsync=off\" -w -t 30 start"
su postgres -c "$PGBIN/createdb -h 127.0.0.1 -U bench bench" 2>/dev/null || true
for f in /docker-entrypoint-initdb.d/*.sql; do su postgres -c "$PGBIN/psql -h 127.0.0.1 -U bench -d bench -f '$f'"; done
node /internal-sink.mjs >/tmp/internal-sink.log 2>&1 &
sed -i 's/port="8080"/port="3000"/' /usr/local/tomcat/conf/server.xml
(
  while [ ! -d /usr/local/tomcat/webapps/ROOT ]; do sleep 1; done
  mkdir -p /usr/local/tomcat/webapps/ROOT/uploads /usr/local/tomcat/webapps/ROOT/downloads
) &
export DB_URL="${DB_URL:-jdbc:postgresql://postgres:5432/bench}" DB_USER="${DB_USER:-bench}" DB_PASSWORD="${DB_PASSWORD:-bench}" VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
exec catalina.sh run
