#!/bin/sh
set -eu
rm -f "/tmp/benchpress-state-${VARIANT:-safe}.json"
exec php -S 0.0.0.0:3000 -t /app/public /app/public/index.php
