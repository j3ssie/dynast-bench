#!/bin/sh
set -eu
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export VARIANT="${VARIANT:-safe}"
export STANDALONE=1
export NETMETA_PORT=13000
export NETMETA_BIND=0.0.0.0

cat >> /etc/hosts <<'HOSTS'
127.0.0.10 edge-proxy
127.0.0.11 edge-bastion
127.0.0.12 edge-ftp
127.0.0.13 edge-mail
127.0.0.20 app-web
127.0.0.21 app-legacy
127.0.0.30 data-postgres
127.0.0.31 data-redis
127.0.0.32 data-redis-secure
127.0.0.33 data-mongo
127.0.0.34 data-elastic
127.0.0.35 data-memcached
127.0.0.40 mgmt-jenkins
127.0.0.41 mgmt-grafana
127.0.0.42 mgmt-rabbitmq
127.0.0.43 mgmt-phpmyadmin
127.0.0.44 mgmt-minio
127.0.0.45 mgmt-snmp
127.0.0.2 scanner
HOSTS

# Loopback 127.0.0.0/8 aliases do not need explicit address creation in Linux,
# but this mirrors the documented standalone topology and is harmless if present.
for ip in 127.0.0.10 127.0.0.11 127.0.0.12 127.0.0.13 127.0.0.20 127.0.0.21 127.0.0.30 127.0.0.31 127.0.0.32 127.0.0.33 127.0.0.34 127.0.0.35 127.0.0.40 127.0.0.41 127.0.0.42 127.0.0.43 127.0.0.44 127.0.0.45; do
  ip addr add "$ip/8" dev lo 2>/dev/null || true
done

exec node /app/simulator.mjs
