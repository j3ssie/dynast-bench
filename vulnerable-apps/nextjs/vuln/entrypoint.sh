#!/bin/sh
set -e
echo "[entrypoint] waiting for database, applying schema..."
npx prisma db push --skip-generate --accept-data-loss
echo "[entrypoint] seeding..."
node prisma/seed.mjs || echo "[entrypoint] seed failed (continuing)"
echo "[entrypoint] starting Next.js (production)..."
exec npm run start
