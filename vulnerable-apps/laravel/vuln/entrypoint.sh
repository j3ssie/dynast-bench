#!/bin/sh
set -e
cd /var/www/html

# Wait for MySQL (compose gates on healthy, but be defensive).
for i in $(seq 1 60); do
  if php -r 'exit(@mysqli_connect(getenv("DB_HOST"), getenv("DB_USERNAME"), getenv("DB_PASSWORD"), getenv("DB_DATABASE")) ? 0 : 1);' 2>/dev/null; then
    break
  fi
  sleep 1
done

# Fresh, byte-identical state on every boot.
php artisan migrate:fresh --seed --force

exec apache2-foreground
