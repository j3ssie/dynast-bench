#!/bin/sh
set -e
php /var/www/seed.php
exec apache2-foreground
