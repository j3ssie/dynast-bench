#!/bin/sh
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in mysql mailpit phpmyadmin; do
  grep -q "[[:space:]]$h$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts
done

export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_NAME="${DB_NAME:-bench}"
export DB_USER="${DB_USER:-bench}"
export DB_PASS="${DB_PASS:-bench}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"

if [ ! -d /var/lib/mysql/mysql ]; then
  mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi

mysqld_safe --datadir=/var/lib/mysql --bind-address=127.0.0.1 --skip-networking=0 >/tmp/mysql.log 2>&1 &
for i in $(seq 1 60); do
  mysqladmin ping -h 127.0.0.1 --silent && break
  sleep 1
done
mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS bench;
CREATE USER IF NOT EXISTS 'bench'@'%' IDENTIFIED BY 'bench';
CREATE USER IF NOT EXISTS 'bench'@'localhost' IDENTIFIED BY 'bench';
CREATE USER IF NOT EXISTS 'bench'@'127.0.0.1' IDENTIFIED BY 'bench';
GRANT ALL PRIVILEGES ON bench.* TO 'bench'@'%';
GRANT ALL PRIVILEGES ON bench.* TO 'bench'@'localhost';
GRANT ALL PRIVILEGES ON bench.* TO 'bench'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

node /usr/local/bin/internal-sink.mjs &
php /var/www/seed.php
exec apache2-foreground
