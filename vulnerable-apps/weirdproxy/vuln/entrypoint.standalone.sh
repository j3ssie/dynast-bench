#!/bin/sh
set -e

# Alias the compose service name to localhost so the baked proxy configs
# (which dial origin:9000) work unchanged in the single-image build.
grep -q "[[:space:]]origin$" /etc/hosts 2>/dev/null || echo "127.0.0.1 origin" >> /etc/hosts

# Origin backend (internal).
ORIGIN_PORT=9000 node /app/origin/server.mjs &

# nginx on :8080 (published as the app-under-test port).
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
sed -i 's/listen 80;/listen 8080;/' /etc/nginx/conf.d/default.conf
nginx -g 'daemon off;' &

# apache on :8081.
sed -i 's/^Listen 80$/Listen 8081/' /etc/apache2/ports.conf
a2dissite 000-default >/dev/null 2>&1 || true
: "${APACHE_RUN_DIR:=/var/run/apache2}"
mkdir -p "$APACHE_RUN_DIR"
apachectl -D FOREGROUND &

# traefik on :8082.
sed -i 's/:80/:8082/' /etc/traefik/traefik.yml
traefik --configFile=/etc/traefik/traefik.yml &

wait
