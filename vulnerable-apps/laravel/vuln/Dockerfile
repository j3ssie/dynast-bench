# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM php:8.3-apache

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl default-mysql-client git libpng-dev libzip-dev libonig-dev unzip \
 && docker-php-ext-install pdo pdo_mysql gd zip \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2.7 /usr/bin/composer /usr/bin/composer

COPY --from=dynast-src /src/docker/apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY --from=dynast-src /src/docker/php.ini /usr/local/etc/php/conf.d/bench.ini
RUN a2enmod rewrite

WORKDIR /var/www/html
COPY --from=dynast-src /src/ /var/www/html
RUN --mount=type=cache,target=/root/.composer --mount=type=cache,target=/root/.cache/composer composer install --no-dev --optimize-autoloader --no-interaction --prefer-dist \
 && mkdir -p storage/framework/sessions storage/framework/views storage/framework/cache \
             storage/logs storage/app/exports bootstrap/cache public/uploads \
 && printf 'seed export marker\n' > storage/app/exports/report.txt \
 && chown -R www-data:www-data storage bootstrap/cache public/uploads

COPY --from=dynast-src /src/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=90s \
  CMD curl -sf http://localhost/api/_verify/health || exit 1
CMD ["/usr/local/bin/entrypoint.sh"]
