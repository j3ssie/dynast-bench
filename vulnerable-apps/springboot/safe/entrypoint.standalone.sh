#!/usr/bin/env sh
set -eu
for h in postgres redis mailpit internal-sink jenkins prometheus; do
  if ! grep -q " $h" /etc/hosts; then echo "127.0.0.1 $h" >> /etc/hosts; fi
done
service postgresql start
su postgres -c "psql -tc \"select 1 from pg_roles where rolname='bench'\" | grep -q 1 || createuser bench" || true
su postgres -c "psql -c \"alter user bench with password 'bench'\"" || true
su postgres -c "psql -tc \"select 1 from pg_database where datname='bench'\" | grep -q 1 || createdb -O bench bench" || true
node /app/internal-sink.mjs &
export SPRING_DATASOURCE_URL="${SPRING_DATASOURCE_URL:-jdbc:postgresql://postgres:5432/bench}"
export SPRING_DATASOURCE_USERNAME="${SPRING_DATASOURCE_USERNAME:-bench}"
export SPRING_DATASOURCE_PASSWORD="${SPRING_DATASOURCE_PASSWORD:-bench}"
exec java ${JAVA_OPTS:-} -jar /app/app.jar
