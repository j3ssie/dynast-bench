#!/bin/sh
set -e
mkdir -p /app/uploads /app/attachments
npm run seed
exec node dist/main.js
