FROM php:8.3-apache

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl default-mysql-client \
 && docker-php-ext-install pdo pdo_mysql mysqli \
 && rm -rf /var/lib/apt/lists/*

COPY app/public/ /var/www/html/
COPY app/inc/ /var/www/inc/
COPY app/seed.php /var/www/seed.php
COPY php.ini /usr/local/etc/php/conf.d/bench.ini
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN mkdir -p /var/www/html/uploads /var/www/html/downloads \
 && chown -R www-data:www-data /var/www/html/uploads /var/www/html/downloads \
 && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=60s \
  CMD curl -sf http://localhost/api/_verify/health.php || exit 1
CMD ["/usr/local/bin/entrypoint.sh"]
